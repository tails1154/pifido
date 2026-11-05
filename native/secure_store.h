#ifndef PIFIDO_SECURE_STORE_H
#define PIFIDO_SECURE_STORE_H

#include <stddef.h>
#include <stdint.h>

/* Load an authenticated encrypted store into a volatile plaintext path.
 * Legacy plaintext stores are deliberately rejected. */
int pifido_secure_store_load(const char *encrypted_path, const char *plain_path,
                             const uint8_t pin_hash[16]);

/* Encrypt the volatile plaintext store with the current PIN-derived key. */
int pifido_secure_store_sync(const char *encrypted_path, const char *plain_path,
                             const uint8_t pin_hash[16]);

#endif
