#ifndef PIFIDO_CRYPTO_H
#define PIFIDO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "store.h"

int pifido_sign_sha256(const struct pifido_credential *credential,
                       const uint8_t digest[32], uint8_t *signature,
                       size_t signature_cap, size_t *signature_len);
int pifido_verify_sha256(const struct pifido_credential *credential,
                         const uint8_t digest[32], const uint8_t *signature,
                         size_t signature_len);

#endif
