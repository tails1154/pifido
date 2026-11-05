#ifndef PIFIDO_CTAP_H
#define PIFIDO_CTAP_H

#include <stddef.h>
#include <stdint.h>
#include "store.h"

int pifido_get_assertion(const uint8_t *request, size_t request_len,
                        struct pifido_store *store, const char *store_path,
                        int user_verified,
                        uint8_t *response, size_t response_cap,
                        size_t *response_len);
int pifido_make_credential(const uint8_t *request, size_t request_len,
                           struct pifido_store *store, const char *store_path,
                           const uint8_t aaguid[16],
                           int user_verified,
                           uint8_t *response, size_t response_cap,
                           size_t *response_len);

#endif
