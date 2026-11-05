#ifndef PIFIDO_PIN_H
#define PIFIDO_PIN_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct evp_pkey_st EVP_PKEY;

struct pifido_pin_state {
    char path[512];
    uint8_t pin_hash[16];
    unsigned retries;
    EVP_PKEY *key_agreement;
    uint8_t token[32];
    int token_valid;
    time_t token_expiry;
};

/* A missing PIN file is initialized once with the configured verifier;
 * existing or malformed state is never silently reset. */
int pifido_pin_init(struct pifido_pin_state *state, const char *path,
                    const uint8_t initial_pin_hash[16]);
void pifido_pin_destroy(struct pifido_pin_state *state);
int pifido_client_pin_command(struct pifido_pin_state *state,
                              const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t response_cap,
                              size_t *response_len);

/* Return a CTAP status byte. On success, *user_verified reflects a valid
 * PIN token authorization carried by makeCredential/getAssertion. */
uint8_t pifido_pin_check_request(struct pifido_pin_state *state,
                                uint8_t command,
                                const uint8_t *request, size_t request_len,
                                int *user_verified);

#endif
