#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

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
