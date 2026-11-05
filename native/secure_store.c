#define _GNU_SOURCE
#include "secure_store.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC "PFS1"
#define SALT_LEN 16
#define NONCE_LEN 12
#define TAG_LEN 16
#define KDF_ROUNDS 200000

static int read_file(const char *path, uint8_t **data, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n <= 0 || n > 4 * 1024 * 1024) { fclose(f); return -1; }
    rewind(f);
    uint8_t *p = malloc((size_t)n);
    if (!p) { fclose(f); return -1; }
    size_t got = fread(p, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) { free(p); return -1; }
    *data = p; *len = got; return 0;
}

static int derive_key(const uint8_t pin_hash[16], const uint8_t salt[SALT_LEN],
                      uint8_t key[32]) {
    static const uint8_t label[] = "PiFIDO credential store v1";
    uint8_t input[sizeof label - 1 + 16];
    memcpy(input, label, sizeof label - 1);
    memcpy(input + sizeof label - 1, pin_hash, 16);
    int ok = PKCS5_PBKDF2_HMAC((const char *)input, sizeof input, salt, SALT_LEN,
                               KDF_ROUNDS, EVP_sha256(), 32, key);
    OPENSSL_cleanse(input, sizeof input);
    return ok == 1 ? 0 : -1;
}

static int atomic_write(const char *path, const uint8_t *data, size_t len) {
    char tmp[4096];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof tmp) return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    int rc = (write(fd, data, len) == (ssize_t)len && fsync(fd) == 0) ? 0 : -1;
    if (fchmod(fd, 0600) != 0) rc = -1;
    if (close(fd) != 0) rc = -1;
    if (rc == 0 && rename(tmp, path) != 0) rc = -1;
    if (rc != 0) unlink(tmp);
    if (rc == 0) {
        char dir[4096];
        const char *slash = strrchr(path, '/');
        size_t dlen = slash ? (size_t)(slash - path) : 1;
        if (dlen >= sizeof dir) return -1;
        if (slash) memcpy(dir, path, dlen); else dir[0] = '.';
        dir[dlen] = '\0';
        int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0 || fsync(dfd) != 0) rc = -1;
        if (dfd >= 0) close(dfd);
    }
    return rc;
}

int pifido_secure_store_sync(const char *encrypted_path, const char *plain_path,
                             const uint8_t pin_hash[16]) {
    uint8_t *plain = NULL; size_t plain_len = 0;
    if (read_file(plain_path, &plain, &plain_len) != 0) return -1;
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN], key[32], tag[TAG_LEN];
    if (RAND_bytes(salt, sizeof salt) != 1 || RAND_bytes(nonce, sizeof nonce) != 1 ||
        derive_key(pin_hash, salt, key) != 0) { free(plain); return -1; }
    uint8_t *record = malloc(4 + SALT_LEN + NONCE_LEN + 4 + plain_len + TAG_LEN);
    if (!record) { OPENSSL_cleanse(key, sizeof key); free(plain); return -1; }
    memcpy(record, MAGIC, 4); memcpy(record + 4, salt, SALT_LEN);
    memcpy(record + 4 + SALT_LEN, nonce, NONCE_LEN);
    uint32_t n = (uint32_t)plain_len;
    record[32] = (uint8_t)(n >> 24); record[33] = (uint8_t)(n >> 16);
    record[34] = (uint8_t)(n >> 8); record[35] = (uint8_t)n;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); int out_n = 0, tail = 0, rc = -1;
    if (ctx && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, NULL, &out_n, record, 36) == 1 &&
        EVP_EncryptUpdate(ctx, record + 36, &out_n, plain, (int)plain_len) == 1 &&
        EVP_EncryptFinal_ex(ctx, record + 36 + out_n, &tail) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) == 1) {
        memcpy(record + 36 + plain_len, tag, TAG_LEN);
        rc = atomic_write(encrypted_path, record, 36 + plain_len + TAG_LEN);
    }
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, sizeof key); OPENSSL_cleanse(tag, sizeof tag);
    OPENSSL_cleanse(plain, plain_len); free(plain); free(record); return rc;
}

int pifido_secure_store_load(const char *encrypted_path, const char *plain_path,
                             const uint8_t pin_hash[16]) {
    uint8_t *record = NULL; size_t record_len = 0;
    if (read_file(encrypted_path, &record, &record_len) != 0) return -1;
    if (record_len < 36 + TAG_LEN || memcmp(record, MAGIC, 4) != 0) {
        free(record); return -2; /* plaintext/unknown format: refuse migration */
    }
    uint32_t plain_len = ((uint32_t)record[32] << 24) | ((uint32_t)record[33] << 16) |
                         ((uint32_t)record[34] << 8) | record[35];
    if ((size_t)plain_len + 36 + TAG_LEN != record_len || plain_len == 0) { free(record); return -1; }
    uint8_t key[32];
    if (derive_key(pin_hash, record + 4, key) != 0) { free(record); return -1; }
    uint8_t *plain = malloc(plain_len); int out_n = 0, tail = 0, rc = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (plain && ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, record + 20) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &out_n, record, 36) == 1 &&
        EVP_DecryptUpdate(ctx, plain, &out_n, record + 36, (int)plain_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            record + 36 + plain_len) == 1 &&
        EVP_DecryptFinal_ex(ctx, plain + out_n, &tail) == 1) {
        rc = atomic_write(plain_path, plain, plain_len);
    }
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, sizeof key);
    if (plain) { OPENSSL_cleanse(plain, plain_len); free(plain); }
    free(record); return rc;
}
