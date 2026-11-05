#define _GNU_SOURCE
#include "pin.h"
#include "cbor.h"

#include <errno.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "pin-test failed at line %d: %s\n", __LINE__, #x); return 1; } } while (0)

static int raw(struct cbor_writer *w, const uint8_t *p, size_t n) {
    if (w->cap - w->pos < n) return -1;
    memcpy(w->data + w->pos, p, n); w->pos += n; return 0;
}

static EVP_PKEY *platform_key(uint8_t x[32], uint8_t y[32], uint8_t *cose,
                              size_t cap, size_t *cose_len) {
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EVP_PKEY *key = EVP_PKEY_new(); BIGNUM *bx = BN_new(), *by = BN_new();
    if (!ec || !key || !bx || !by || EC_KEY_generate_key(ec) != 1) goto fail;
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const EC_POINT *point = EC_KEY_get0_public_key(ec);
    if (EC_POINT_get_affine_coordinates(group, point, bx, by, NULL) != 1 ||
        BN_bn2binpad(bx, x, 32) != 32 || BN_bn2binpad(by, y, 32) != 32) goto fail;
    BN_free(bx); BN_free(by);
    bx = by = NULL;
    if (EVP_PKEY_assign_EC_KEY(key, ec) != 1) goto fail;
    ec = NULL;
    struct cbor_writer w = {cose, cap, 0};
    if (!(cbor_write_map_len(&w, 5) == 0 && cbor_write_uint(&w, 1) == 0 &&
          cbor_write_uint(&w, 2) == 0 && cbor_write_uint(&w, 3) == 0 &&
          cbor_write_int(&w, -25) == 0 && cbor_write_int(&w, -1) == 0 &&
          cbor_write_uint(&w, 1) == 0 && cbor_write_int(&w, -2) == 0 &&
          cbor_write_bytes(&w, x, 32) == 0 && cbor_write_int(&w, -3) == 0 &&
          cbor_write_bytes(&w, y, 32) == 0)) goto fail;
    *cose_len = w.pos;
    return key;
fail:
    EC_KEY_free(ec); BN_free(bx); BN_free(by); EVP_PKEY_free(key); return NULL;
}

static EVP_PKEY *peer_key(const uint8_t x[32], const uint8_t y[32]) {
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EVP_PKEY *key = EVP_PKEY_new(); BIGNUM *bx = BN_bin2bn(x, 32, NULL);
    BIGNUM *by = BN_bin2bn(y, 32, NULL);
    EC_POINT *point = ec ? EC_POINT_new(EC_KEY_get0_group(ec)) : NULL;
    if (!ec || !key || !bx || !by || !point ||
        EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ec), point, bx, by, NULL) != 1 ||
        EC_KEY_set_public_key(ec, point) != 1 || EC_KEY_check_key(ec) != 1 ||
        EVP_PKEY_assign_EC_KEY(key, ec) != 1) {
        EC_POINT_free(point); BN_free(bx); BN_free(by); EC_KEY_free(ec); EVP_PKEY_free(key);
        return NULL;
    }
    EC_POINT_free(point); BN_free(bx); BN_free(by); return key;
}

static int shared_secret(EVP_PKEY *local, EVP_PKEY *peer, uint8_t out[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local, NULL); uint8_t raw_secret[32]; size_t n = sizeof raw_secret;
    uint8_t digest[EVP_MAX_MD_SIZE]; unsigned int dn = 0;
    int ok = ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, peer) > 0 &&
        EVP_PKEY_derive(ctx, raw_secret, &n) > 0 && n == 32 &&
        EVP_Digest(raw_secret, n, digest, &dn, EVP_sha256(), NULL) == 1 && dn >= 32;
    if (ok) memcpy(out, digest, 32);
    EVP_PKEY_CTX_free(ctx); OPENSSL_cleanse(raw_secret, sizeof raw_secret);
    OPENSSL_cleanse(digest, sizeof digest); return ok ? 0 : -1;
}

static int aes(int encrypt, const uint8_t secret[32], const uint8_t *in,
               size_t len, uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); uint8_t iv[16] = {0}; int n = 0, tail = 0;
    if (!ctx) return -1;
    int ok = encrypt ? EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret, iv)
                     : EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret, iv);
    if (ok != 1 || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto err;
    ok = encrypt ? EVP_EncryptUpdate(ctx, out, &n, in, (int)len)
                 : EVP_DecryptUpdate(ctx, out, &n, in, (int)len);
    if (ok != 1) goto err;
    ok = encrypt ? EVP_EncryptFinal_ex(ctx, out + n, &tail)
                 : EVP_DecryptFinal_ex(ctx, out + n, &tail);
    EVP_CIPHER_CTX_free(ctx); return ok == 1 && (size_t)(n + tail) == len ? 0 : -1;
err:
    EVP_CIPHER_CTX_free(ctx); return -1;
}

static int decode_auth_key(const uint8_t *response, size_t len, uint8_t x[32], uint8_t y[32]) {
    struct cbor_reader r = {response, len, 0}; size_t map, cose;
    if (cbor_read_map_len(&r, &map) || map != 1) return -1;
    uint64_t k; if (cbor_read_uint(&r, &k) || k != 1 || cbor_read_map_len(&r, &cose)) return -1;
    for (size_t i = 0; i < cose; i++) {
        int64_t key; if (cbor_read_int(&r, &key)) return -1;
        if (key == -2 || key == -3) {
            const uint8_t *p; size_t n;
            if (cbor_read_bytes(&r, &p, &n) || n != 32) return -1;
            memcpy(key == -2 ? x : y, p, 32);
        } else if (cbor_skip(&r)) return -1;
    }
    return r.pos == r.len ? 0 : -1;
}

static int get_key_agreement(struct pifido_pin_state *state, uint8_t auth_x[32], uint8_t auth_y[32]) {
    uint8_t req[8] = {0xa2,0x01,0x01,0x02,0x02}, response[256]; size_t n = 0;
    if (pifido_client_pin_command(state, req, 5, response, sizeof response, &n) != 0) return -1;
    return decode_auth_key(response, n, auth_x, auth_y);
}

static int get_token(struct pifido_pin_state *state, const char *pin, int *status_out,
                     uint8_t token[32]) {
    uint8_t ax[32], ay[32], px[32], py[32], cose[128], request[256], response[256];
    size_t cose_len = 0, response_len = 0;
    EVP_PKEY *host = platform_key(px, py, cose, sizeof cose, &cose_len);
    if (!host || get_key_agreement(state, ax, ay) != 0) { EVP_PKEY_free(host); return -1; }
    EVP_PKEY *auth = peer_key(ax, ay); uint8_t secret[32];
    if (!auth || shared_secret(host, auth, secret) != 0) { EVP_PKEY_free(host); EVP_PKEY_free(auth); return -1; }
    uint8_t digest[EVP_MAX_MD_SIZE], pin_hash[16], encrypted_hash[16]; unsigned int digest_len = 0;
    if (EVP_Digest(pin, strlen(pin), digest, &digest_len, EVP_sha256(), NULL) != 1 || digest_len < 16) return -1;
    memcpy(pin_hash, digest, 16);
    if (aes(1, secret, pin_hash, sizeof pin_hash, encrypted_hash) != 0) return -1;
    struct cbor_writer w = {request, sizeof request, 0};
    if (cbor_write_map_len(&w, 4) || cbor_write_uint(&w, 1) || cbor_write_uint(&w, 1) ||
        cbor_write_uint(&w, 2) || cbor_write_uint(&w, 5) || cbor_write_uint(&w, 3) ||
        raw(&w, cose, cose_len) || cbor_write_uint(&w, 6) ||
        cbor_write_bytes(&w, encrypted_hash, sizeof encrypted_hash)) return -1;
    *status_out = pifido_client_pin_command(state, request, w.pos, response, sizeof response, &response_len);
    if (*status_out == 0) {
        struct cbor_reader rr = {response, response_len, 0}; size_t count;
        const uint8_t *enc; size_t enc_len;
        if (cbor_read_map_len(&rr, &count) || count != 1) return -1;
        uint64_t key; if (cbor_read_uint(&rr, &key) || key != 2 ||
            cbor_read_bytes(&rr, &enc, &enc_len) || enc_len != 32 || rr.pos != rr.len ||
            aes(0, secret, enc, enc_len, token) != 0) return -1;
    }
    EVP_PKEY_free(host); EVP_PKEY_free(auth);
    OPENSSL_cleanse(secret, sizeof secret); OPENSSL_cleanse(digest, sizeof digest);
    OPENSSL_cleanse(pin_hash, sizeof pin_hash); OPENSSL_cleanse(encrypted_hash, sizeof encrypted_hash);
    return 0;
}

static int change_pin(struct pifido_pin_state *state, const char *old_pin,
                      const char *new_pin, int *status_out) {
    uint8_t ax[32], ay[32], px[32], py[32], cose[128], request[512], response[256];
    size_t cose_len = 0, response_len = 0;
    EVP_PKEY *host = platform_key(px, py, cose, sizeof cose, &cose_len);
    if (!host || get_key_agreement(state, ax, ay) != 0) { EVP_PKEY_free(host); return -1; }
    EVP_PKEY *auth = peer_key(ax, ay); uint8_t secret[32];
    if (!auth || shared_secret(host, auth, secret) != 0) { EVP_PKEY_free(host); EVP_PKEY_free(auth); return -1; }
    uint8_t digest[EVP_MAX_MD_SIZE], old_hash[16], encrypted_hash[16]; unsigned int digest_len = 0;
    uint8_t new_block[64] = {0}, encrypted_new[64], auth_data[80], pin_auth[16], mac[EVP_MAX_MD_SIZE];
    if (EVP_Digest(old_pin, strlen(old_pin), digest, &digest_len, EVP_sha256(), NULL) != 1 || digest_len < 16) return -1;
    memcpy(old_hash, digest, 16);
    if (aes(1, secret, old_hash, 16, encrypted_hash) != 0) return -1;
    size_t new_len = strlen(new_pin);
    if (new_len > 63) return -1;
    memcpy(new_block, new_pin, new_len);
    if (aes(1, secret, new_block, sizeof new_block, encrypted_new) != 0) return -1;
    memcpy(auth_data, encrypted_new, 64); memcpy(auth_data + 64, encrypted_hash, 16);
    unsigned int mac_len = 0;
    if (!HMAC(EVP_sha256(), secret, sizeof secret, auth_data, sizeof auth_data, mac, &mac_len) || mac_len < 16)
        return -1;
    memcpy(pin_auth, mac, 16);
    struct cbor_writer w = {request, sizeof request, 0};
    if (cbor_write_map_len(&w, 6) || cbor_write_uint(&w, 1) || cbor_write_uint(&w, 1) ||
        cbor_write_uint(&w, 2) || cbor_write_uint(&w, 4) || cbor_write_uint(&w, 3) ||
        raw(&w, cose, cose_len) || cbor_write_uint(&w, 4) || cbor_write_bytes(&w, pin_auth, 16) ||
        cbor_write_uint(&w, 5) || cbor_write_bytes(&w, encrypted_new, 64) ||
        cbor_write_uint(&w, 6) || cbor_write_bytes(&w, encrypted_hash, 16)) return -1;
    *status_out = pifido_client_pin_command(state, request, w.pos, response, sizeof response, &response_len);
    EVP_PKEY_free(host); EVP_PKEY_free(auth); OPENSSL_cleanse(secret, sizeof secret);
    OPENSSL_cleanse(digest, sizeof digest); OPENSSL_cleanse(old_hash, sizeof old_hash);
    OPENSSL_cleanse(new_block, sizeof new_block); OPENSSL_cleanse(mac, sizeof mac);
    return 0;
}

int main(void) {
    char directory[] = "/tmp/pifido-pin-test.XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char path[256]; CHECK(snprintf(path, sizeof path, "%s/pin.bin", directory) > 0);
    struct pifido_pin_state state;
    uint8_t initial_hash[16], pin_digest[EVP_MAX_MD_SIZE]; unsigned int pin_digest_len = 0;
    CHECK(EVP_Digest("1154", 4, pin_digest, &pin_digest_len, EVP_sha256(), NULL) == 1 && pin_digest_len >= 16);
    memcpy(initial_hash, pin_digest, 16);
    CHECK(pifido_pin_init(&state, path, initial_hash) == 0 && state.retries == 8);
    uint8_t token[32]; int status = -1;
    CHECK(get_token(&state, "1154", &status, token) == 0 && status == 0);
    uint8_t client_hash[32] = {0}, pin_auth[16], mac[EVP_MAX_MD_SIZE]; unsigned int mac_len = 0;
    CHECK(HMAC(EVP_sha256(), token, sizeof token, client_hash, sizeof client_hash, mac, &mac_len) != NULL && mac_len >= 16);
    memcpy(pin_auth, mac, sizeof pin_auth);
    uint8_t assertion_request[128]; struct cbor_writer w = {assertion_request, sizeof assertion_request, 0};
    CHECK(cbor_write_map_len(&w, 4) == 0 && cbor_write_uint(&w, 1) == 0 &&
          cbor_write_text(&w, "example.test", 12) == 0 && cbor_write_uint(&w, 2) == 0 &&
          cbor_write_bytes(&w, client_hash, sizeof client_hash) == 0 && cbor_write_uint(&w, 6) == 0 &&
          cbor_write_bytes(&w, pin_auth, sizeof pin_auth) == 0 && cbor_write_uint(&w, 7) == 0 &&
          cbor_write_uint(&w, 1) == 0);
    int user_verified = 0;
    CHECK(pifido_pin_check_request(&state, 0x02, assertion_request, w.pos, &user_verified) == 0 && user_verified);
    CHECK(get_token(&state, "9999", &status, token) == 0 && status == 0x31 && state.retries == 7);
    pifido_pin_destroy(&state);
    CHECK(pifido_pin_init(&state, path, initial_hash) == 0 && state.retries == 7);
    CHECK(get_token(&state, "1154", &status, token) == 0 && status == 0 && state.retries == 8);
    CHECK(change_pin(&state, "1154", "2277", &status) == 0 && status == 0);
    CHECK(get_token(&state, "1154", &status, token) == 0 && status == 0x31);
    CHECK(get_token(&state, "2277", &status, token) == 0 && status == 0);
    pifido_pin_destroy(&state);
    unlink(path); rmdir(directory);
    puts("CTAP clientPIN protocol 1 test passed");
    return 0;
}
