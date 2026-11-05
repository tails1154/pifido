#ifndef PIFIDO_CTAP_H
#define PIFIDO_CTAP_H

#include <stddef.h>
#include <stdint.h>
#include "store.h"

int pifido_get_assertion(const uint8_t *request, size_t request_len,
                        struct pifido_store *store, const char *store_path,
                        uint8_t *response, size_t response_cap,
                        size_t *response_len);

#endif
