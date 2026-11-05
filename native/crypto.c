#include "crypto.h"

#include <string.h>
#include <mbedtls/pk.h>

int pifido_sign_sha256(const struct pifido_credential *credential,
                       const uint8_t digest[32], uint8_t *signature,
                       size_t signature_cap, size_t *signature_len) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int rc = mbedtls_pk_parse_key(&pk, credential->private_key_der,
                                  credential->private_key_der_len, NULL, 0);
    if (rc == 0)
        rc = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, digest, 32,
                             signature, signature_cap, signature_len);
    mbedtls_pk_free(&pk);
    return rc;
}

int pifido_verify_sha256(const struct pifido_credential *credential,
                         const uint8_t digest[32], const uint8_t *signature,
                         size_t signature_len) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int rc = mbedtls_pk_parse_public_key(&pk, credential->public_key_der,
                                         credential->public_key_der_len);
    if (rc == 0)
        rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, 32,
                               signature, signature_len);
    mbedtls_pk_free(&pk);
    return rc;
}
