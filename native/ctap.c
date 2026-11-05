#include "ctap.h"
#include "cbor.h"
#include "crypto.h"

#include <string.h>
#include <mbedtls/md.h>

int pifido_get_assertion(const uint8_t *request, size_t request_len,
                        struct pifido_store *store, const char *store_path,
                        uint8_t *response, size_t response_cap,
                        size_t *response_len) {
    struct cbor_reader r = { request, request_len, 0 };
    size_t map_len;
    const char *rp = NULL; size_t rp_len = 0;
    const uint8_t *client_hash = NULL; size_t client_hash_len = 0;
    const uint8_t *allow_id = NULL; size_t allow_id_len = 0;
    if (cbor_read_map_len(&r, &map_len) != 0) return -1;
    for (size_t i = 0; i < map_len; ++i) {
        uint64_t key;
        if (cbor_read_uint(&r, &key) != 0) return -1;
        if (key == 1) {
            if (cbor_read_text(&r, &rp, &rp_len) != 0) return -1;
        } else if (key == 2) {
            if (cbor_read_bytes(&r, &client_hash, &client_hash_len) != 0) return -1;
        } else if (key == 3) {
            size_t n;
            if (cbor_read_array_len(&r, &n) != 0) return -1;
            if (n > 0) {
                size_t fields;
                if (cbor_read_map_len(&r, &fields) != 0) return -1;
                for (size_t j = 0; j < fields; ++j) {
                    uint64_t k;
                    if (cbor_read_uint(&r, &k) != 0) return -1;
                    if (k == 2) {
                        if (cbor_read_bytes(&r, &allow_id, &allow_id_len) != 0) return -1;
                    } else if (cbor_skip(&r) != 0) return -1;
                }
                for (size_t j = 1; j < n; ++j) if (cbor_skip(&r) != 0) return -1;
            }
        } else if (cbor_skip(&r) != 0) return -1;
    }
    if (!rp || !client_hash || client_hash_len != 32) return -1;
    struct pifido_credential *credential = NULL;
    for (size_t i = 0; i < store->count; ++i) {
        struct pifido_credential *candidate = &store->credentials[i];
        if (strlen(candidate->rp_id) != rp_len || memcmp(candidate->rp_id, rp, rp_len) != 0) continue;
        if (allow_id && (allow_id_len != candidate->credential_id_len ||
                         memcmp(allow_id, candidate->credential_id, allow_id_len) != 0)) continue;
        credential = candidate; break;
    }
    if (!credential) return -1;

    uint8_t rp_hash[32];
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   (const unsigned char *)rp, rp_len, rp_hash) != 0) return -1;
    uint32_t count;
    if (pifido_store_increment_counter(store_path, credential->credential_id,
                                        credential->credential_id_len, &count) != 0) return -1;
    credential->signature_count = count;
    uint8_t auth_data[37];
    memcpy(auth_data, rp_hash, 32); auth_data[32] = 0x01;
    auth_data[33] = (uint8_t)(count >> 24); auth_data[34] = (uint8_t)(count >> 16);
    auth_data[35] = (uint8_t)(count >> 8); auth_data[36] = (uint8_t)count;
    uint8_t signed_data[69], digest[32], signature[128]; size_t signature_len = 0;
    memcpy(signed_data, auth_data, 37); memcpy(signed_data + 37, client_hash, 32);
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   signed_data, sizeof signed_data, digest) != 0) return -1;
    if (pifido_sign_sha256(credential, digest, signature, sizeof signature, &signature_len) != 0) return -1;

    struct cbor_writer w = { response, response_cap, 0 };
    if (cbor_write_map_len(&w, 4) != 0 || cbor_write_uint(&w, 1) != 0 ||
        cbor_write_map_len(&w, 1) != 0 || cbor_write_uint(&w, 2) != 0 ||
        cbor_write_bytes(&w, credential->credential_id, credential->credential_id_len) != 0 ||
        cbor_write_uint(&w, 2) != 0 || cbor_write_bytes(&w, auth_data, sizeof auth_data) != 0 ||
        cbor_write_uint(&w, 3) != 0 || cbor_write_bytes(&w, signature, signature_len) != 0 ||
        cbor_write_uint(&w, 4) != 0 || cbor_write_map_len(&w, 1) != 0 ||
        cbor_write_uint(&w, 1) != 0 || cbor_write_bytes(&w, credential->user_id, credential->user_id_len) != 0)
        return -1;
    *response_len = w.pos;
    return 0;
}
