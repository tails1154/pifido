#ifndef PIFIDO_U2F_H
#define PIFIDO_U2F_H

#include <stddef.h>
#include <stdint.h>

#include "store.h"

/* Process a CTAP1/U2F APDU transported by CTAPHID_MSG. Responses include the
 * two-byte U2F status word. User presence is supplied by the caller policy. */
int pifido_u2f_apdu(const uint8_t *apdu, size_t apdu_len,
                    struct pifido_store *store, const char *store_path,
                    uint8_t *out, size_t out_cap, size_t *out_len);

#endif
