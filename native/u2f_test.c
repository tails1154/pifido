#define _GNU_SOURCE
#define _XOPEN_SOURCE 700
#include "u2f.h"
#include "crypto.h"

#include <assert.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Some strict-libc toolchains hide this POSIX declaration unless their
 * feature macro was supplied on the command line. */
extern int mkstemp(char *);

static void write_all(int fd, const char *text) { assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text)); assert(fsync(fd) == 0); }
static unsigned status(const uint8_t *response, size_t len) { assert(len >= 2); return ((unsigned)response[len - 2] << 8) | response[len - 1]; }
static void sha256(const uint8_t *in, size_t len, uint8_t out[32]) {
    unsigned int n = 0;
    assert(EVP_Digest(in, len, out, &n, EVP_sha256(), NULL) == 1 && n == 32);
}
static size_t apdu(uint8_t *out, uint8_t ins, uint8_t p1, const uint8_t *body, size_t body_len) {
    assert(body_len <= 255); out[0] = 0; out[1] = ins; out[2] = p1; out[3] = 0; out[4] = (uint8_t)body_len; memcpy(out + 5, body, body_len); return body_len + 5;
}

static size_t extended_apdu(uint8_t *out, uint8_t ins, uint8_t p1,
                            const uint8_t *body, size_t body_len) {
    assert(body_len <= 0xffff);
    out[0] = 0; out[1] = ins; out[2] = p1; out[3] = 0; out[4] = 0;
    out[5] = (uint8_t)(body_len >> 8); out[6] = (uint8_t)body_len;
    memcpy(out + 7, body, body_len);
    /* Chrome commonly appends an extended Le field. */
    out[7 + body_len] = 0; out[8 + body_len] = 0;
    return body_len + 9;
}
int main(void) {
    char path[] = "/tmp/pifido-u2f-test.XXXXXX";
    int fd = mkstemp(path); assert(fd >= 0); write_all(fd, "{\"credentials\":[]}"); close(fd);
    struct pifido_store store; assert(pifido_store_load(path, &store) == 0);
    uint8_t request[300], response[2048]; size_t req_len, response_len;
    req_len = apdu(request, 0x03, 0, NULL, 0);
    assert(pifido_u2f_apdu(request, req_len, &store, path, response, sizeof response, &response_len) == 0);
    assert(response_len == 8 && !memcmp(response, "U2F_V2\x90\0", 8));
    uint8_t body[65] = {0};
    memset(body, 0x11, 32); memset(body + 32, 0x22, 32);
    req_len = apdu(request, 0x01, 0x03, body, 64);
    assert(pifido_u2f_apdu(request, req_len, &store, path, response, sizeof response, &response_len) == 0 && status(response, response_len) == 0x9000);
    assert(response[0] == 0x05 && response[66] == 32 && store.count == 1);
    uint8_t key_handle[32]; memcpy(key_handle, response + 67, sizeof key_handle);
    /* Verify the registration attestation over the exact U2F byte sequence;
     * this catches malformed leading-zero/app/challenge ordering. */
    const unsigned char *certificate_at = response + 99;
    X509 *certificate = d2i_X509(NULL, &certificate_at, (long)(response_len - 99 - 2));
    assert(certificate);
    size_t certificate_len = (size_t)(certificate_at - (response + 99));
    EVP_PKEY *attestation_public = X509_get_pubkey(certificate);
    EVP_MD_CTX *verify = EVP_MD_CTX_new();
    uint8_t registration_signed[1 + 32 + 32 + 1 + 32 + 65];
    registration_signed[0] = 0;
    memcpy(registration_signed + 1, body + 32, 32);
    memcpy(registration_signed + 33, body, 32);
    registration_signed[65] = 32;
    memcpy(registration_signed + 66, key_handle, 32);
    memcpy(registration_signed + 98, response + 1, 65);
    assert(verify && EVP_DigestVerifyInit(verify, NULL, EVP_sha256(), NULL, attestation_public) == 1 &&
           EVP_DigestVerifyUpdate(verify, registration_signed, sizeof registration_signed) == 1 &&
           EVP_DigestVerifyFinal(verify, response + 99 + certificate_len,
                                 response_len - 99 - certificate_len - 2) == 1);
    EVP_MD_CTX_free(verify); EVP_PKEY_free(attestation_public); X509_free(certificate);
    uint8_t auth_body[97]; memset(auth_body, 0x33, 32); memset(auth_body + 32, 0x22, 32); auth_body[64] = 32; memcpy(auth_body + 65, key_handle, 32);
    req_len = apdu(request, 0x02, 0x07, auth_body, sizeof auth_body);
    assert(pifido_u2f_apdu(request, req_len, &store, path, response, sizeof response, &response_len) == 0 && status(response, response_len) == 0x6985);
    req_len = apdu(request, 0x02, 0x03, auth_body, sizeof auth_body);
    assert(pifido_u2f_apdu(request, req_len, &store, path, response, sizeof response, &response_len) == 0 && status(response, response_len) == 0x9000 && response[0] == 1);
    uint8_t authentication_signed[69], digest[32];
    memcpy(authentication_signed, auth_body + 32, 32);
    memcpy(authentication_signed + 32, response, 5);
    memcpy(authentication_signed + 37, auth_body, 32);
    sha256(authentication_signed, sizeof authentication_signed, digest);
    assert(pifido_verify_sha256(&store.credentials[0], digest, response + 5, response_len - 7) == 0);
    assert(pifido_store_load(path, &store) == 0 && store.count == 1 && store.credentials[0].signature_count == 1);
    unlink(path);
    puts("U2F Java-semantics compatibility test passed");
    return 0;
}
