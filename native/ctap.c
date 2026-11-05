#include "ctap.h"
#include "cbor.h"
#include "crypto.h"

#include <string.h>
#include <mbedtls/md.h>
#include <openssl/rand.h>

int pifido_get_assertion(const uint8_t *request, size_t request_len,
                        struct pifido_store *store, const char *store_path,
                        int user_verified,
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
    memcpy(auth_data, rp_hash, 32); auth_data[32] = (uint8_t)(0x01 | (user_verified ? 0x04 : 0));
    auth_data[33] = (uint8_t)(count >> 24); auth_data[34] = (uint8_t)(count >> 16);
    auth_data[35] = (uint8_t)(count >> 8); auth_data[36] = (uint8_t)count;
    uint8_t signed_data[69], digest[32], signature[128]; size_t signature_len = 0;
    memcpy(signed_data, auth_data, 37); memcpy(signed_data + 37, client_hash, 32);
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   signed_data, sizeof signed_data, digest) != 0) return -1;
    if (pifido_sign_sha256(credential, digest, signature, sizeof signature, &signature_len) != 0) return -1;

    struct cbor_writer w = { response, response_cap, 0 };
    /* Match the Java response exactly: credential descriptor, authenticator
     * data, and signature. The Java model carries userId internally but does
     * not serialize CTAP map key 4; emitting an extra key makes the CBOR map
     * length inconsistent and Chromium rejects the response. */
    if (cbor_write_map_len(&w, 3) != 0 || cbor_write_uint(&w, 1) != 0 ||
        cbor_write_map_len(&w, 2) != 0 || cbor_write_text(&w, "id", 2) != 0 ||
        cbor_write_bytes(&w, credential->credential_id, credential->credential_id_len) != 0 ||
        cbor_write_text(&w, "type", 4) != 0 || cbor_write_text(&w, "public-key", 10) != 0 ||
        cbor_write_uint(&w, 2) != 0 || cbor_write_bytes(&w, auth_data, sizeof auth_data) != 0 ||
        cbor_write_uint(&w, 3) != 0 || cbor_write_bytes(&w, signature, signature_len) != 0)
        return -1;
    *response_len = w.pos;
    return 0;
}

int pifido_make_credential(const uint8_t *request, size_t request_len,
                           struct pifido_store *store, const char *store_path,
                           const uint8_t aaguid[16],
                           int user_verified,
                           uint8_t *response, size_t response_cap,
                           size_t *response_len) {
#define MC_FAIL(code) return -(code)
    struct cbor_reader r = { request, request_len, 0 }; size_t fields;
    const uint8_t *client_hash = NULL, *user_id = NULL; size_t hash_len = 0, user_len = 0;
    char rp_id[256] = {0}; int have_alg = 0;
    if (cbor_read_map_len(&r, &fields) != 0) MC_FAIL(10);
    for (size_t i = 0; i < fields; ++i) {
        uint64_t key; if (cbor_read_uint(&r, &key) != 0) MC_FAIL(11);
        if (key == 1) { if (cbor_read_bytes(&r, &client_hash, &hash_len) != 0) MC_FAIL(12); }
        else if (key == 2) {
            size_t n; if (cbor_read_map_len(&r, &n) != 0) MC_FAIL(13);
            for (size_t j=0;j<n;++j) { const char *k; size_t kl; if (cbor_read_text(&r,&k,&kl)!=0) MC_FAIL(14);
                if (kl == 2 && memcmp(k, "id", 2) == 0) { const char *p; size_t l; if (cbor_read_text(&r,&p,&l)!=0 || l >= sizeof rp_id) MC_FAIL(15); memcpy(rp_id,p,l); rp_id[l]='\0'; }
                else if (cbor_skip(&r)!=0) MC_FAIL(16); }
        } else if (key == 3) {
            size_t n; if (cbor_read_map_len(&r, &n) != 0) MC_FAIL(17);
            for (size_t j=0;j<n;++j) { const char *k; size_t kl; if (cbor_read_text(&r,&k,&kl)!=0) MC_FAIL(18);
                if (kl == 2 && memcmp(k, "id", 2) == 0) { const uint8_t *p; if (cbor_read_bytes(&r,&p,&user_len)!=0 || user_len > 128) MC_FAIL(19); user_id=p; }
                else if (cbor_skip(&r)!=0) MC_FAIL(20); }
        } else if (key == 4) {
            size_t n; if (cbor_read_array_len(&r,&n)!=0) MC_FAIL(21);
            for (size_t j=0;j<n;++j) { size_t m; if(cbor_read_map_len(&r,&m)!=0) MC_FAIL(22); int64_t alg=0;
                for (size_t k=0;k<m;++k) { const char *mk; size_t mkl; if(cbor_read_text(&r,&mk,&mkl)!=0) MC_FAIL(23);
                    if (mkl == 3 && memcmp(mk, "alg", 3) == 0) { if(cbor_read_int(&r,&alg)!=0) MC_FAIL(24); } else if(cbor_skip(&r)!=0) MC_FAIL(25); }
                if (alg == -7) have_alg = 1; }
        } else if (cbor_skip(&r)!=0) MC_FAIL(26);
    }
    if (!client_hash || hash_len != 32 || !rp_id[0] || !user_id || !have_alg) MC_FAIL(27);
    uint8_t private_der[256], public_der[256], x[32], y[32], cred_id[32]; size_t priv_len=0,pub_len=0;
    if (RAND_bytes(cred_id, sizeof cred_id) != 1 || pifido_generate_p256(private_der,sizeof private_der,&priv_len,public_der,sizeof public_der,&pub_len,x,y)!=0) MC_FAIL(28);
    if (pifido_store_add_credential(store_path, rp_id, user_id, user_len, cred_id, sizeof cred_id, private_der, priv_len, public_der, pub_len)!=0) MC_FAIL(29);
    struct pifido_credential temp = {0}; memcpy(temp.private_key_der, private_der, priv_len); temp.private_key_der_len=priv_len;
    uint8_t rp_hash[32]; if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),(const unsigned char*)rp_id,strlen(rp_id),rp_hash)!=0) MC_FAIL(30);
    uint8_t auth[1024]; size_t ap=0; memcpy(auth,rp_hash,32); ap=32; auth[ap++]=(uint8_t)(0x41 | (user_verified ? 0x04 : 0)); memset(auth+ap,0,4); ap+=4; memcpy(auth+ap,aaguid,16); ap+=16; auth[ap++]=0; auth[ap++]=32; memcpy(auth+ap,cred_id,32); ap+=32;
    struct cbor_writer cw={auth+ap,sizeof auth-ap,0};
    if(cbor_write_map_len(&cw,5)||cbor_write_uint(&cw,1)||cbor_write_uint(&cw,2)||cbor_write_uint(&cw,3)||cbor_write_int(&cw,-7)||cbor_write_int(&cw,-1)||cbor_write_uint(&cw,1)||cbor_write_int(&cw,-2)||cbor_write_bytes(&cw,x,32)||cbor_write_int(&cw,-3)||cbor_write_bytes(&cw,y,32)) MC_FAIL(31);
    ap += cw.pos;
    uint8_t signed_data[1056], digest[32], sig[128]; size_t sig_len=0; memcpy(signed_data,auth,ap); memcpy(signed_data+ap,client_hash,32);
    if(mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),signed_data,ap+32,digest)!=0 || pifido_sign_sha256(&temp,digest,sig,sizeof sig,&sig_len)!=0) MC_FAIL(32);
    struct cbor_writer out={response,response_cap,0};
    if(cbor_write_map_len(&out,3)||cbor_write_uint(&out,1)||cbor_write_text(&out,"packed",6)||cbor_write_uint(&out,2)||cbor_write_bytes(&out,auth,ap)||cbor_write_uint(&out,3)||cbor_write_map_len(&out,2)||cbor_write_uint(&out,1)||cbor_write_int(&out,-7)||cbor_write_uint(&out,3)||cbor_write_bytes(&out,sig,sig_len)) MC_FAIL(33);
    /* The Java authenticator keeps the newly created resident credential in
     * its in-memory configuration. Reload our crash-consistent store so a
     * GetAssertion in the same USB session can find it without a reboot. */
    if (pifido_store_load(store_path, store) != 0) MC_FAIL(34);
    *response_len=out.pos; return 0;
#undef MC_FAIL
}
