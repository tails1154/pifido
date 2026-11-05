#include "u2f.h"

#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <mbedtls/md.h>

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define SW_NO_ERROR                 0x9000
#define SW_WRONG_LENGTH             0x6700
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA               0x6a80
#define SW_INS_NOT_SUPPORTED        0x6d00
#define SW_INTERNAL_ERROR           0x6f00

/* The Java implementation creates this in process memory.  Keeping it
 * process-local deliberately preserves that behavior: credentials persist,
 * but this development attestation identity is not represented as a vendor
 * trust anchor. */
static EVP_PKEY *attestation_key;
static X509 *attestation_certificate;

static int append_status(uint8_t *out, size_t cap, size_t *pos, unsigned status) {
    if (*pos + 2 > cap) return -1;
    out[(*pos)++] = (uint8_t)(status >> 8);
    out[(*pos)++] = (uint8_t)status;
    return 0;
}

static int digest_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, len, out) == 0 ? 0 : -1;
}

static void hex_lower(const uint8_t *in, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[len * 2] = '\0';
}

static int ensure_attestation(void) {
    if (attestation_key && attestation_certificate) return 0;
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    X509_NAME *name;
    int rc = -1;
    if (!keygen || EVP_PKEY_keygen_init(keygen) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keygen, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(keygen, &key) <= 0 || !(cert = X509_new())) goto out;
    /* The Pi Zero commonly boots with its clock at the Unix epoch. A
     * certificate issued relative to that unset clock is already expired by
     * the Chromebook. Keep this development-only self-signed certificate in
     * a fixed broad window; this does not create a vendor trust anchor. */
    const time_t not_before = (time_t)1577836800;  /* 2020-01-01 */
    const time_t not_after = (time_t)4102444800;   /* 2100-01-01 */
    if (X509_set_version(cert, 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
        !ASN1_TIME_set(X509_getm_notBefore(cert), not_before) ||
        !ASN1_TIME_set(X509_getm_notAfter(cert), not_after) ||
        X509_set_pubkey(cert, key) != 1) goto out;
    name = X509_get_subject_name(cert);
    if (!name || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                             (const unsigned char *)"PiFIDO U2F Attestation", -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert, name) != 1 || X509_sign(cert, key, EVP_sha256()) <= 0) goto out;
    attestation_key = key; key = NULL;
    attestation_certificate = cert; cert = NULL;
    rc = 0;
out:
    EVP_PKEY_free(key);
    X509_free(cert);
    EVP_PKEY_CTX_free(keygen);
    return rc;
}

static int sign_attestation(const uint8_t *data, size_t len, uint8_t *sig, size_t cap, size_t *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t n = cap;
    int rc = -1;
    if (ctx && EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, attestation_key) == 1 &&
        EVP_DigestSignUpdate(ctx, data, len) == 1 && EVP_DigestSignFinal(ctx, sig, &n) == 1) {
        *sig_len = n;
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int public_point(const uint8_t *public_der, size_t public_len, uint8_t point[65]) {
    const unsigned char *cursor = public_der;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &cursor, (long)public_len);
    EC_KEY *ec = key ? EVP_PKEY_get1_EC_KEY(key) : NULL;
    const EC_GROUP *group = ec ? EC_KEY_get0_group(ec) : NULL;
    const EC_POINT *pub = ec ? EC_KEY_get0_public_key(ec) : NULL;
    size_t n = group && pub ? EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, point, 65, NULL) : 0;
    EC_KEY_free(ec);
    EVP_PKEY_free(key);
    return n == 65 ? 0 : -1;
}

static int handle_register(const uint8_t *data, size_t data_len, struct pifido_store *store,
                           const char *store_path, uint8_t *out, size_t cap, size_t *out_len) {
    uint8_t private_der[256], public_der[256], x[32], y[32], id[32], point[65];
    size_t private_len = 0, public_len = 0, pos = 0, cert_len, sig_len = 0;
    uint8_t cert[1024], signature[128], signed_data[1 + 32 + 32 + 1 + 32 + 65];
    char app_hex[65];
    if (data_len < 64) {
        if (append_status(out, cap, &pos, SW_WRONG_LENGTH) != 0) return -1;
        *out_len = pos;
        return 0;
    }
    if (RAND_bytes(id, sizeof id) != 1 ||
        pifido_generate_p256(private_der, sizeof private_der, &private_len,
                             public_der, sizeof public_der, &public_len, x, y) != 0 ||
        public_point(public_der, public_len, point) != 0) goto internal;
    hex_lower(data + 32, 32, app_hex);
    if (pifido_store_add_credential(store_path, app_hex, (const uint8_t *)"", 0,
                                    id, sizeof id, private_der, private_len,
                                    public_der, public_len) != 0 ||
        pifido_store_load(store_path, store) != 0) goto internal;
    if (ensure_attestation() != 0) goto internal;
    cert_len = (size_t)i2d_X509(attestation_certificate, NULL);
    if (!cert_len || cert_len > sizeof cert || 1 + 65 + 1 + sizeof id + cert_len + 2 > cap) goto internal;
    unsigned char *cert_cursor = cert;
    if (i2d_X509(attestation_certificate, &cert_cursor) != (int)cert_len) goto internal;
    pos = 0;
    out[pos++] = 0x05;
    memcpy(out + pos, point, sizeof point); pos += sizeof point;
    out[pos++] = sizeof id;
    memcpy(out + pos, id, sizeof id); pos += sizeof id;
    signed_data[0] = 0;
    memcpy(signed_data + 1, data + 32, 32);
    memcpy(signed_data + 33, data, 32);
    signed_data[65] = sizeof id;
    memcpy(signed_data + 66, id, sizeof id);
    memcpy(signed_data + 98, point, sizeof point);
    if (sign_attestation(signed_data, sizeof signed_data, signature, sizeof signature, &sig_len) != 0 ||
        pos + cert_len + sig_len + 2 > cap) goto internal;
    memcpy(out + pos, cert, cert_len); pos += cert_len;
    memcpy(out + pos, signature, sig_len); pos += sig_len;
    if (append_status(out, cap, &pos, SW_NO_ERROR) != 0) return -1;
    *out_len = pos;
    return 0;
internal:
    pos = 0;
    if (append_status(out, cap, &pos, SW_INTERNAL_ERROR) != 0) return -1;
    *out_len = pos;
    return 0;
}

static int handle_authenticate(const uint8_t *data, size_t data_len, uint8_t p1,
                               struct pifido_store *store, const char *store_path,
                               uint8_t *out, size_t cap, size_t *out_len) {
    uint8_t digest[32], signature[128], signed_data[32 + 1 + 4 + 32];
    size_t pos = 0, signature_len = 0;
    char app_hex[65];
    if (data_len < 65) goto wrong_length;
    size_t id_len = data[64];
    if (!id_len || id_len > data_len - 65) goto wrong_length;
    hex_lower(data + 32, 32, app_hex);
    struct pifido_credential *credential = NULL;
    for (size_t i = 0; i < store->count; ++i) {
        struct pifido_credential *candidate = &store->credentials[i];
        if (strcmp(candidate->rp_id, app_hex) == 0 && candidate->credential_id_len == id_len &&
            memcmp(candidate->credential_id, data + 65, id_len) == 0) { credential = candidate; break; }
    }
    if (!credential) goto wrong_data;
    /* CHECK_ONLY is non-signing and must not consume user presence or the
     * monotonic counter. A recognized key handle reports conditions not
     * satisfied; an unknown handle was handled above as wrong data. */
    if (p1 == 0x07) goto conditions;
    if (p1 != 0x03) goto wrong_data;
    uint32_t counter;
    if (pifido_store_increment_counter(store_path, credential->credential_id,
                                       credential->credential_id_len, &counter) != 0) goto internal;
    credential->signature_count = counter;
    memcpy(signed_data, data + 32, 32);
    signed_data[32] = 0x01;
    signed_data[33] = (uint8_t)(counter >> 24);
    signed_data[34] = (uint8_t)(counter >> 16);
    signed_data[35] = (uint8_t)(counter >> 8);
    signed_data[36] = (uint8_t)counter;
    memcpy(signed_data + 37, data, 32);
    if (digest_sha256(signed_data, sizeof signed_data, digest) != 0 ||
        pifido_sign_sha256(credential, digest, signature, sizeof signature, &signature_len) != 0 ||
        5 + signature_len + 2 > cap) goto internal;
    out[pos++] = 0x01;
    memcpy(out + pos, signed_data + 33, 4); pos += 4;
    memcpy(out + pos, signature, signature_len); pos += signature_len;
    if (append_status(out, cap, &pos, SW_NO_ERROR) != 0) return -1;
    *out_len = pos;
    return 0;
wrong_length:
    if (append_status(out, cap, &pos, SW_WRONG_LENGTH) != 0) return -1;
    *out_len = pos; return 0;
wrong_data:
    if (append_status(out, cap, &pos, SW_WRONG_DATA) != 0) return -1;
    *out_len = pos; return 0;
conditions:
    if (append_status(out, cap, &pos, SW_CONDITIONS_NOT_SATISFIED) != 0) return -1;
    *out_len = pos; return 0;
internal:
    if (append_status(out, cap, &pos, SW_INTERNAL_ERROR) != 0) return -1;
    *out_len = pos; return 0;
}

int pifido_u2f_apdu(const uint8_t *apdu, size_t apdu_len, struct pifido_store *store,
                    const char *store_path, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t pos = 0;
    if (!apdu || !store || !store_path || !out || !out_len || apdu_len < 2) {
        if (out && out_cap >= 2) { append_status(out, out_cap, &pos, SW_INS_NOT_SUPPORTED); *out_len = pos; return 0; }
        return -1;
    }
    uint8_t ins = apdu[1];
    if (ins == 0x03) {
        static const uint8_t version[] = "U2F_V2";
        if (sizeof version - 1 + 2 > out_cap) return -1;
        memcpy(out, version, sizeof version - 1); pos = sizeof version - 1;
        if (append_status(out, out_cap, &pos, SW_NO_ERROR) != 0) return -1;
        *out_len = pos; return 0;
    }
    if (apdu_len < 5) goto bad_length;
    size_t header, data_len;
    if (apdu_len == 5 + apdu[4]) { header = 5; data_len = apdu[4]; }
    else if (apdu_len >= 7) {
        header = 7; data_len = ((size_t)apdu[5] << 8) | apdu[6];
        if (data_len > apdu_len - header) data_len = apdu_len - header;
    } else goto bad_length;
    if (ins == 0x01 && data_len >= 64 && (apdu[2] == 0x03 || apdu[2] == 0x83))
        return handle_register(apdu + header, data_len, store, store_path, out, out_cap, out_len);
    if (ins == 0x02 && data_len >= 65)
        return handle_authenticate(apdu + header, data_len, apdu[2], store, store_path, out, out_cap, out_len);
    if (append_status(out, out_cap, &pos, SW_INS_NOT_SUPPORTED) != 0) return -1;
    *out_len = pos; return 0;
bad_length:
    if (append_status(out, out_cap, &pos, SW_WRONG_LENGTH) != 0) return -1;
    *out_len = pos; return 0;
}
