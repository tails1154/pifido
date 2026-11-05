#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

int pifido_sign_sha256(const struct pifido_credential *credential,
                       const uint8_t digest[32], uint8_t *signature,
                       size_t signature_cap, size_t *signature_len) {
    const unsigned char *p = credential->private_key_der;
    EVP_PKEY *key = d2i_AutoPrivateKey(NULL, &p, (long)credential->private_key_der_len);
    if (!key) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    int rc = -1;
    if (ctx && EVP_PKEY_sign_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0) {
        size_t n = signature_cap;
        if (EVP_PKEY_sign(ctx, signature, &n, digest, 32) > 0) {
            *signature_len = n; rc = 0;
        }
    }
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key);
    return rc;
}

int pifido_verify_sha256(const struct pifido_credential *credential,
                         const uint8_t digest[32], const uint8_t *signature,
                         size_t signature_len) {
    const unsigned char *p = credential->public_key_der;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &p, (long)credential->public_key_der_len);
    if (!key) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    int rc = -1;
    if (ctx && EVP_PKEY_verify_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0)
        rc = EVP_PKEY_verify(ctx, signature, signature_len, digest, 32) == 1 ? 0 : -1;
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key);
    return rc;
}

int pifido_generate_p256(uint8_t *private_der, size_t private_cap, size_t *private_len,
                         uint8_t *public_der, size_t public_cap, size_t *public_len,
                         uint8_t x[32], uint8_t y[32]) {
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL; EC_KEY *ec = NULL; const EC_POINT *point; const EC_GROUP *group;
    int rc = -1;
    if (!gen || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(gen, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0) goto out;
    /* Java's stored private keys are PKCS#8.  Keep the native store
     * byte-compatible instead of writing OpenSSL's SEC1 ECPrivateKey. */
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(key);
    if (!p8) goto out;
    int n = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
    int p = i2d_PUBKEY(key, NULL);
    if (n <= 0 || p <= 0 || (size_t)n > private_cap || (size_t)p > public_cap) {
        PKCS8_PRIV_KEY_INFO_free(p8);
        goto out;
    }
    unsigned char *np = private_der; if (i2d_PKCS8_PRIV_KEY_INFO(p8, &np) != n) {
        PKCS8_PRIV_KEY_INFO_free(p8);
        goto out;
    }
    PKCS8_PRIV_KEY_INFO_free(p8);
    np = public_der; if (i2d_PUBKEY(key, &np) != p) goto out;
    ec = EVP_PKEY_get1_EC_KEY(key); if (!ec) goto out;
    group = EC_KEY_get0_group(ec); point = EC_KEY_get0_public_key(ec);
    if (!group || !point) goto out;
    BIGNUM *bx = BN_new(), *by = BN_new();
    if (!bx || !by || EC_POINT_get_affine_coordinates(group, point, bx, by, NULL) != 1 ||
        BN_bn2binpad(bx, x, 32) != 32 || BN_bn2binpad(by, y, 32) != 32) { BN_free(bx); BN_free(by); goto out; }
    BN_free(bx); BN_free(by); *private_len = (size_t)n; *public_len = (size_t)p; rc = 0;
out:
    EC_KEY_free(ec); EVP_PKEY_free(key); EVP_PKEY_CTX_free(gen); return rc;
}
