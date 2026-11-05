#ifndef PIFIDO_STORE_H
#define PIFIDO_STORE_H

#include <stddef.h>
#include <stdint.h>

#define PIFIDO_MAX_CREDENTIALS 128

struct pifido_credential {
    char rp_id[256];
    uint8_t user_id[128];
    size_t user_id_len;
    uint8_t credential_id[64];
    size_t credential_id_len;
    uint8_t private_key_der[256];
    size_t private_key_der_len;
    uint8_t public_key_der[256];
    size_t public_key_der_len;
    uint32_t signature_count;
};

struct pifido_store {
    struct pifido_credential credentials[PIFIDO_MAX_CREDENTIALS];
    size_t count;
};

int pifido_store_load(const char *path, struct pifido_store *store);
int pifido_base64_decode(const char *text, uint8_t *out, size_t cap, size_t *out_len);
size_t pifido_base64_encode(const uint8_t *in, size_t len, char *out, size_t cap);
int pifido_store_add_credential(const char *path, const char *rp_id,
                                const uint8_t *user_id, size_t user_id_len,
                                const uint8_t *credential_id, size_t credential_id_len,
                                const uint8_t *private_key_der, size_t private_key_der_len,
                                const uint8_t *public_key_der, size_t public_key_der_len);
int pifido_store_increment_counter(const char *path, const uint8_t *credential_id,
                                   size_t credential_id_len, uint32_t *new_count);
int pifido_store_delete_credential(const char *path, const uint8_t *credential_id,
                                   size_t credential_id_len);
const char *pifido_store_last_error(void);

#endif
