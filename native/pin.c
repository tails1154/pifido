#define _GNU_SOURCE
#include "pin.h"
#include "cbor.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PIN_RETRIES_MAX 8u
#define PIN_PROTOCOL_ONE 1u
#define PIN_TOKEN_LIFETIME 30
#define CTAP_OK 0x00
#define CTAP_INVALID_PARAMETER 0x02
#define CTAP_INVALID_CBOR 0x12
#define CTAP_MISSING_PARAMETER 0x14
#define CTAP_PIN_INVALID 0x31
#define CTAP_PIN_BLOCKED 0x32
#define CTAP_PIN_AUTH_INVALID 0x33
#define CTAP_PIN_NOT_SET 0x35
#define CTAP_PIN_REQUIRED 0x36
#define CTAP_PIN_POLICY_VIOLATION 0x37
#define CTAP_OTHER 0x7f

struct pin_request {
    uint64_t protocol, subcommand;
    int has_protocol, has_subcommand;
    const uint8_t *host_key; size_t host_key_len;
    const uint8_t *pin_auth; size_t pin_auth_len;
    const uint8_t *new_pin_enc; size_t new_pin_enc_len;
    const uint8_t *pin_hash_enc; size_t pin_hash_enc_len;
};

static int write_all(int fd, const uint8_t *p, size_t n) {
    while (n) {
        ssize_t wr = write(fd, p, n);
        if (wr < 0 && errno == EINTR) continue;
        if (wr <= 0) return -1;
        p += (size_t)wr; n -= (size_t)wr;
    }
    return 0;
}

static int save_state(const struct pifido_pin_state *s) {
    uint8_t rec[21] = {'P','F','P','1'};
    memcpy(rec + 4, s->pin_hash, 16);
    rec[20] = (uint8_t)s->retries;
    char tmp[600], dir[512];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", s->path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof tmp) return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 && errno == EEXIST) {
        if (unlink(tmp) != 0) return -1;
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    }
    if (fd < 0) return -1;
    int rc = write_all(fd, rec, sizeof rec);
    if (rc == 0 && fsync(fd) != 0) rc = -1;
    if (fchmod(fd, 0600) != 0) rc = -1;
    if (close(fd) != 0) rc = -1;
    if (rc == 0 && rename(tmp, s->path) != 0) rc = -1;
    if (rc != 0) unlink(tmp);
    if (rc != 0) return -1;
    if (strlen(s->path) >= sizeof dir) return -1;
    strcpy(dir, s->path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        if (slash == dir) slash[1] = '\0';
        else *slash = '\0';
    } else strcpy(dir, ".");
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return -1;
    rc = fsync(dfd);
    close(dfd);
    return rc;
}

static int hash_pin(const uint8_t *pin, size_t pin_len, uint8_t out[16]) {
    uint8_t digest[EVP_MAX_MD_SIZE]; unsigned int n = 0;
    if (EVP_Digest(pin, pin_len, digest, &n, EVP_sha256(), NULL) != 1 || n < 16) {
        OPENSSL_cleanse(digest, sizeof digest); return -1;
    }
    memcpy(out, digest, 16);
    OPENSSL_cleanse(digest, sizeof digest);
    return 0;
}

int pifido_pin_init(struct pifido_pin_state *s, const char *path,
                    const uint8_t initial_pin_hash[16]) {
    if (!s || !path || !initial_pin_hash || strlen(path) >= sizeof s->path) return -1;
    memset(s, 0, sizeof *s);
    strcpy(s->path, path);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        uint8_t rec[22]; size_t got = 0;
        while (got < sizeof rec) {
            ssize_t n = read(fd, rec + got, sizeof rec - got);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            got += (size_t)n;
        }
        close(fd);
        if (got != 21 || memcmp(rec, "PFP1", 4) != 0 || rec[20] > PIN_RETRIES_MAX) {
            OPENSSL_cleanse(rec, sizeof rec); return -1;
        }
        memcpy(s->pin_hash, rec + 4, 16);
        s->retries = rec[20];
        OPENSSL_cleanse(rec, sizeof rec);
        if (chmod(path, 0600) != 0) return -1;
        return 0;
    }
    if (errno != ENOENT) return -1;
    memcpy(s->pin_hash, initial_pin_hash, 16);
    s->retries = PIN_RETRIES_MAX;
    if (save_state(s) != 0) { OPENSSL_cleanse(s, sizeof *s); return -1; }
    return 0;
}

void pifido_pin_destroy(struct pifido_pin_state *s) {
    if (!s) return;
    EVP_PKEY_free(s->key_agreement);
    OPENSSL_cleanse(s, sizeof *s);
}

static EVP_PKEY *generate_key(uint8_t x[32], uint8_t y[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL; EC_KEY *ec = NULL;
    BIGNUM *bx = NULL, *by = NULL;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) goto err;
    ec = EVP_PKEY_get1_EC_KEY(key);
    if (!ec) goto err;
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const EC_POINT *point = EC_KEY_get0_public_key(ec);
    bx = BN_new(); by = BN_new();
    if (!group || !point || !bx || !by ||
        EC_POINT_get_affine_coordinates(group, point, bx, by, NULL) != 1 ||
        BN_bn2binpad(bx, x, 32) != 32 || BN_bn2binpad(by, y, 32) != 32) goto err;
    BN_free(bx); BN_free(by); EC_KEY_free(ec); EVP_PKEY_CTX_free(ctx);
    return key;
err:
    BN_free(bx); BN_free(by); EC_KEY_free(ec); EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(x, 32); OPENSSL_cleanse(y, 32);
    return NULL;
}

static EVP_PKEY *parse_host_key(const uint8_t *data, size_t len) {
    struct cbor_reader r = {data, len, 0}; size_t count;
    int have_type = 0, have_alg = 0, have_curve = 0;
    uint64_t type = 0; int64_t alg = 0, curve = 0;
    const uint8_t *x = NULL, *y = NULL; size_t xn = 0, yn = 0;
    if (cbor_read_map_len(&r, &count) != 0 || count > 16) return NULL;
    for (size_t i = 0; i < count; i++) {
        int64_t key;
        if (cbor_read_int(&r, &key) != 0) return NULL;
        if (key == 1) { if (cbor_read_uint(&r, &type) != 0) return NULL; have_type = 1; }
        else if (key == 3) { if (cbor_read_int(&r, &alg) != 0) return NULL; have_alg = 1; }
        else if (key == -1) { if (cbor_read_int(&r, &curve) != 0) return NULL; have_curve = 1; }
        else if (key == -2) { if (cbor_read_bytes(&r, &x, &xn) != 0) return NULL; }
        else if (key == -3) { if (cbor_read_bytes(&r, &y, &yn) != 0) return NULL; }
        else if (cbor_skip(&r) != 0) return NULL;
    }
    if (r.pos != r.len || !have_type || type != 2 || !have_alg || alg != -25 ||
        !have_curve || curve != 1 || !x || !y || xn != 32 || yn != 32) return NULL;
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EVP_PKEY *key = EVP_PKEY_new();
    BIGNUM *bx = BN_bin2bn(x, (int)xn, NULL), *by = BN_bin2bn(y, (int)yn, NULL);
    EC_POINT *point = ec ? EC_POINT_new(EC_KEY_get0_group(ec)) : NULL;
    int ok = ec && key && bx && by && point &&
        EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ec), point, bx, by, NULL) == 1 &&
        EC_KEY_set_public_key(ec, point) == 1 && EC_KEY_check_key(ec) == 1 &&
        EVP_PKEY_assign_EC_KEY(key, ec) == 1;
    BN_free(bx); BN_free(by); EC_POINT_free(point);
    if (!ok) { EC_KEY_free(ec); EVP_PKEY_free(key); return NULL; }
    return key;
}

static int derive_secret(struct pifido_pin_state *s, const uint8_t *cose,
                         size_t cose_len, uint8_t secret[32]) {
    EVP_PKEY *peer = parse_host_key(cose, cose_len);
    EVP_PKEY_CTX *ctx = NULL; uint8_t raw[32]; size_t n = sizeof raw;
    uint8_t digest[EVP_MAX_MD_SIZE]; unsigned int digest_len = 0;
    int ok = 0;
    if (!peer || !s->key_agreement) goto out;
    ctx = EVP_PKEY_CTX_new(s->key_agreement, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, raw, &n) <= 0 || n != 32 ||
        EVP_Digest(raw, n, digest, &digest_len, EVP_sha256(), NULL) != 1 ||
        digest_len < 32) goto out;
    memcpy(secret, digest, 32); ok = 1;
out:
    OPENSSL_cleanse(raw, sizeof raw); OPENSSL_cleanse(digest, sizeof digest);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer);
    return ok ? 0 : -1;
}

static int crypt_pin(int encrypt, const uint8_t key[32], const uint8_t *in,
                     size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (in_len == 0 || (in_len & 15) || out_cap < in_len || in_len > INT_MAX) return -1;
    uint8_t iv[16] = {0}; int n = 0, tail = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = encrypt
        ? EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)
        : EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (ok != 1 || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto err;
    ok = encrypt ? EVP_EncryptUpdate(ctx, out, &n, in, (int)in_len)
                 : EVP_DecryptUpdate(ctx, out, &n, in, (int)in_len);
    if (ok != 1) goto err;
    ok = encrypt ? EVP_EncryptFinal_ex(ctx, out + n, &tail)
                 : EVP_DecryptFinal_ex(ctx, out + n, &tail);
    if (ok != 1 || (size_t)(n + tail) != in_len) goto err;
    *out_len = (size_t)(n + tail); EVP_CIPHER_CTX_free(ctx); return 0;
err:
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(out, out_cap); return -1;
}

static int mac16(const uint8_t key[32], const uint8_t *data, size_t len,
                 uint8_t out[16]) {
    uint8_t mac[EVP_MAX_MD_SIZE]; unsigned int n = 0;
    if (!HMAC(EVP_sha256(), key, 32, data, len, mac, &n) || n < 16) {
        OPENSSL_cleanse(mac, sizeof mac); return -1;
    }
    memcpy(out, mac, 16); OPENSSL_cleanse(mac, sizeof mac); return 0;
}

static int parse_pin_request(const uint8_t *data, size_t len,
                             struct pin_request *q) {
    struct cbor_reader r = {data, len, 0}; size_t count;
    memset(q, 0, sizeof *q);
    if (cbor_read_map_len(&r, &count) != 0 || count > 16) return -1;
    for (size_t i = 0; i < count; i++) {
        uint64_t k;
        if (cbor_read_uint(&r, &k) != 0) return -1;
        if (k == 1) { if (cbor_read_uint(&r, &q->protocol) != 0) return -1; q->has_protocol = 1; }
        else if (k == 2) { if (cbor_read_uint(&r, &q->subcommand) != 0) return -1; q->has_subcommand = 1; }
        else if (k >= 3 && k <= 6) {
            const uint8_t *v; size_t n;
            size_t start = r.pos;
            if (k == 3) {
                if (cbor_skip(&r) != 0) return -1;
                q->host_key = data + start; q->host_key_len = r.pos - start;
            } else {
                if (cbor_read_bytes(&r, &v, &n) != 0) return -1;
                if (k == 4) { q->pin_auth = v; q->pin_auth_len = n; }
                if (k == 5) { q->new_pin_enc = v; q->new_pin_enc_len = n; }
                if (k == 6) { q->pin_hash_enc = v; q->pin_hash_enc_len = n; }
            }
        } else if (cbor_skip(&r) != 0) return -1;
    }
    return r.pos == r.len ? 0 : -1;
}

static int write_cose_key(struct pifido_pin_state *s, struct cbor_writer *w) {
    uint8_t x[32], y[32];
    EVP_PKEY_free(s->key_agreement); s->key_agreement = NULL;
    s->key_agreement = generate_key(x, y);
    if (!s->key_agreement) return -1;
    int rc = cbor_write_map_len(w, 5) || cbor_write_uint(w, 1) || cbor_write_uint(w, 2) ||
        cbor_write_uint(w, 3) || cbor_write_int(w, -25) ||
        cbor_write_int(w, -1) || cbor_write_uint(w, 1) ||
        cbor_write_int(w, -2) || cbor_write_bytes(w, x, sizeof x) ||
        cbor_write_int(w, -3) || cbor_write_bytes(w, y, sizeof y);
    OPENSSL_cleanse(x, sizeof x); OPENSSL_cleanse(y, sizeof y);
    return rc ? -1 : 0;
}

static int decrypt_pin(const uint8_t secret[32], const uint8_t *encrypted,
                       size_t encrypted_len, uint8_t pin[64], size_t *pin_len) {
    if (encrypted_len != 64) return -1;
    size_t n;
    if (crypt_pin(0, secret, encrypted, encrypted_len, pin, 64, &n) != 0 || n != 64) return -1;
    size_t len = 64;
    while (len && pin[len - 1] == 0) len--;
    if (len < 4 || len > 63) return -1;
    /* Validate UTF-8 and count code points; reject overlong forms, surrogates,
     * invalid continuation bytes, and code points above U+10FFFF. */
    size_t points = 0;
    for (size_t i = 0; i < len;) {
        uint8_t c = pin[i]; size_t seq; uint32_t cp;
        if (c < 0x80) { seq = 1; cp = c; }
        else if ((c & 0xe0) == 0xc0) { seq = 2; cp = c & 0x1f; }
        else if ((c & 0xf0) == 0xe0) { seq = 3; cp = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { seq = 4; cp = c & 0x07; }
        else return -1;
        if (i + seq > len) return -1;
        for (size_t j = 1; j < seq; j++) {
            if ((pin[i + j] & 0xc0) != 0x80) return -1;
            cp = (cp << 6) | (pin[i + j] & 0x3f);
        }
        if ((seq == 2 && cp < 0x80) || (seq == 3 && cp < 0x800) ||
            (seq == 4 && cp < 0x10000) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff)) return -1;
        points++; i += seq;
    }
    if (points < 4 || pin[len - 1] == 0) return -1;
    *pin_len = len; return 0;
}

static uint8_t persist_wrong_pin(struct pifido_pin_state *s) {
    if (s->retries) s->retries--;
    if (save_state(s) != 0) return CTAP_OTHER;
    return s->retries ? CTAP_PIN_INVALID : CTAP_PIN_BLOCKED;
}

int pifido_client_pin_command(struct pifido_pin_state *s,
                              const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t response_cap,
                              size_t *response_len) {
    struct pin_request q;
    *response_len = 0;
    if (parse_pin_request(request, request_len, &q) != 0) return CTAP_INVALID_CBOR;
    if (!q.has_protocol || !q.has_subcommand) return CTAP_MISSING_PARAMETER;
    if (q.protocol != PIN_PROTOCOL_ONE) return CTAP_INVALID_PARAMETER;
    struct cbor_writer w = {response, response_cap, 0};
    if (q.subcommand == 1) {
        if (cbor_write_map_len(&w, 1) || cbor_write_uint(&w, 3) ||
            cbor_write_uint(&w, s->retries)) return CTAP_OTHER;
        *response_len = w.pos; return CTAP_OK;
    }
    if (q.subcommand == 2) {
        s->token_valid = 0; OPENSSL_cleanse(s->token, sizeof s->token);
        if (cbor_write_map_len(&w, 1) || cbor_write_uint(&w, 1) ||
            write_cose_key(s, &w) != 0) return CTAP_OTHER;
        *response_len = w.pos; return CTAP_OK;
    }
    if (s->retries == 0) return CTAP_PIN_BLOCKED;
    if (q.subcommand == 3) return CTAP_PIN_AUTH_INVALID;
    if (!q.host_key || !q.host_key_len) return CTAP_MISSING_PARAMETER;
    if (q.subcommand == 4 && !q.pin_auth) return CTAP_MISSING_PARAMETER;
    if (q.subcommand == 4 && q.pin_auth_len != 16) return CTAP_PIN_AUTH_INVALID;
    uint8_t secret[32], expected[16], plaintext[64], computed_hash[16]; size_t plain_len = 0;
    uint8_t status = CTAP_INVALID_PARAMETER;
    if (derive_secret(s, q.host_key, q.host_key_len, secret) != 0) goto done;
    if (q.subcommand != 4 && q.subcommand != 5) { status = 0x3e; goto done; }
    if (!q.pin_hash_enc || q.pin_hash_enc_len != 16) { status = CTAP_MISSING_PARAMETER; goto done; }
    if (q.subcommand == 4 && q.new_pin_enc_len != 64) { status = CTAP_MISSING_PARAMETER; goto done; }
    if (q.subcommand == 4 && !q.new_pin_enc) { status = CTAP_MISSING_PARAMETER; goto done; }
    if (q.subcommand == 5 && q.new_pin_enc) { status = CTAP_INVALID_PARAMETER; goto done; }
    uint8_t auth_data[80]; size_t auth_len = 0;
    if (q.subcommand == 4) {
        memcpy(auth_data, q.new_pin_enc, 64); memcpy(auth_data + 64, q.pin_hash_enc, 16); auth_len = 80;
        if (mac16(secret, auth_data, auth_len, expected) != 0) { status = CTAP_OTHER; goto done; }
        if (CRYPTO_memcmp(expected, q.pin_auth, 16) != 0) { status = CTAP_PIN_AUTH_INVALID; goto done; }
    }
    if (crypt_pin(0, secret, q.pin_hash_enc, q.pin_hash_enc_len, plaintext,
                  sizeof plaintext, &plain_len) != 0 || plain_len != 16) {
        status = CTAP_INVALID_PARAMETER; goto done;
    }
    if (CRYPTO_memcmp(plaintext, s->pin_hash, 16) != 0) {
        status = persist_wrong_pin(s); goto done;
    }
    if (q.subcommand == 5) {
        uint8_t encrypted_token[32]; size_t encrypted_token_len = 0;
        s->token_valid = 0; OPENSSL_cleanse(s->token, sizeof s->token);
        if (RAND_bytes(s->token, sizeof s->token) != 1 ||
            crypt_pin(1, secret, s->token, sizeof s->token, encrypted_token,
                      sizeof encrypted_token, &encrypted_token_len) != 0) { status = CTAP_OTHER; goto done; }
        if (cbor_write_map_len(&w, 1) || cbor_write_uint(&w, 2) ||
            cbor_write_bytes(&w, encrypted_token, encrypted_token_len) != 0) {
            OPENSSL_cleanse(encrypted_token, sizeof encrypted_token);
            status = CTAP_OTHER; goto done;
        }
        *response_len = w.pos;
        OPENSSL_cleanse(encrypted_token, sizeof encrypted_token);
        s->token_valid = 1; s->token_expiry = time(NULL) + PIN_TOKEN_LIFETIME;
        s->retries = PIN_RETRIES_MAX;
        if (save_state(s) != 0) { s->token_valid = 0; status = CTAP_OTHER; goto done; }
        status = CTAP_OK; goto done;
    }
    if (decrypt_pin(secret, q.new_pin_enc, q.new_pin_enc_len, plaintext, &plain_len) != 0 ||
        hash_pin(plaintext, plain_len, computed_hash) != 0) {
        status = CTAP_PIN_POLICY_VIOLATION; goto done;
    }
    uint8_t old_hash[16]; memcpy(old_hash, s->pin_hash, sizeof old_hash);
    memcpy(s->pin_hash, computed_hash, sizeof s->pin_hash);
    s->retries = PIN_RETRIES_MAX; s->token_valid = 0;
    OPENSSL_cleanse(s->token, sizeof s->token);
    if (save_state(s) != 0) { memcpy(s->pin_hash, old_hash, sizeof old_hash); status = CTAP_OTHER; goto done; }
    status = CTAP_OK;
done:
    OPENSSL_cleanse(secret, sizeof secret); OPENSSL_cleanse(expected, sizeof expected);
    OPENSSL_cleanse(plaintext, sizeof plaintext); OPENSSL_cleanse(computed_hash, sizeof computed_hash);
    EVP_PKEY_free(s->key_agreement); s->key_agreement = NULL;
    return status;
}

static int parse_uv_option(struct cbor_reader *r, int *uv) {
    size_t n;
    if (cbor_read_map_len(r, &n) != 0 || n > 32) return -1;
    for (size_t i = 0; i < n; i++) {
        const char *key; size_t key_len;
        if (cbor_read_text(r, &key, &key_len) != 0) return -1;
        if (key_len == 2 && memcmp(key, "uv", 2) == 0) {
            if (r->pos >= r->len) return -1;
            uint8_t b = r->data[r->pos++];
            if (b != 0xf4 && b != 0xf5) return -1;
            *uv = b == 0xf5;
        } else if (cbor_skip(r) != 0) return -1;
    }
    return 0;
}

uint8_t pifido_pin_check_request(struct pifido_pin_state *s, uint8_t command,
                                 const uint8_t *request, size_t request_len,
                                 int *user_verified) {
    struct cbor_reader r = {request, request_len, 0}; size_t count;
    const uint8_t *client_hash = NULL, *pin_auth = NULL;
    size_t hash_len = 0, auth_len = 0;
    uint64_t protocol = 0; int has_protocol = 0, uv = 0;
    uint64_t hash_key, options_key, auth_key, protocol_key;
    if (command == 0x01) { hash_key = 1; options_key = 7; auth_key = 8; protocol_key = 9; }
    else if (command == 0x02) { hash_key = 2; options_key = 5; auth_key = 6; protocol_key = 7; }
    else return CTAP_INVALID_PARAMETER;
    *user_verified = 0;
    if (cbor_read_map_len(&r, &count) != 0 || count > 64) return CTAP_INVALID_CBOR;
    for (size_t i = 0; i < count; i++) {
        uint64_t k;
        if (cbor_read_uint(&r, &k) != 0) return CTAP_INVALID_CBOR;
        if (k == hash_key) {
            if (cbor_read_bytes(&r, &client_hash, &hash_len) != 0) return CTAP_INVALID_CBOR;
        } else if (k == options_key) {
            if (parse_uv_option(&r, &uv) != 0) return CTAP_INVALID_CBOR;
        } else if (k == auth_key) {
            if (cbor_read_bytes(&r, &pin_auth, &auth_len) != 0) return CTAP_INVALID_CBOR;
        } else if (k == protocol_key) {
            if (cbor_read_uint(&r, &protocol) != 0) return CTAP_INVALID_CBOR;
            has_protocol = 1;
        } else if (cbor_skip(&r) != 0) return CTAP_INVALID_CBOR;
    }
    if (r.pos != r.len) return CTAP_INVALID_CBOR;
    if (!pin_auth) return uv ? CTAP_PIN_REQUIRED : CTAP_OK;
    if (!has_protocol || !client_hash || hash_len != 32 || auth_len != 16)
        return CTAP_MISSING_PARAMETER;
    if (protocol != PIN_PROTOCOL_ONE) return CTAP_INVALID_PARAMETER;
    if (!s->token_valid || time(NULL) > s->token_expiry) {
        s->token_valid = 0; OPENSSL_cleanse(s->token, sizeof s->token);
        return CTAP_PIN_AUTH_INVALID;
    }
    uint8_t expected[16];
    int ok = mac16(s->token, client_hash, hash_len, expected) == 0 &&
        CRYPTO_memcmp(expected, pin_auth, 16) == 0;
    OPENSSL_cleanse(expected, sizeof expected);
    if (!ok) return CTAP_PIN_AUTH_INVALID;
    *user_verified = 1;
    return CTAP_OK;
}
