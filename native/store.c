#define _GNU_SOURCE
#include "store.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t pifido_base64_encode(const uint8_t *in, size_t len, char *out, size_t cap) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t w = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        size_t needed = w + 4;
        if (needed + 1 > cap) return 0;
        out[w++] = alphabet[(v >> 18) & 63];
        out[w++] = alphabet[(v >> 12) & 63];
        out[w++] = i + 1 < len ? alphabet[(v >> 6) & 63] : '=';
        out[w++] = i + 2 < len ? alphabet[v & 63] : '=';
    }
    out[w] = '\0';
    return w;
}

int pifido_base64_decode(const char *text, uint8_t *out, size_t cap, size_t *out_len) {
    int val = 0, bits = -8;
    size_t n = 0;
    for (const char *p = text; *p; ++p) {
        if (*p == '=') break;
        int x = b64_value(*p);
        if (x < 0) continue;
        val = (val << 6) | x;
        bits += 6;
        if (bits >= 0) {
            if (n >= cap) return -1;
            out[n++] = (uint8_t)((val >> bits) & 0xff);
            bits -= 8;
        }
    }
    *out_len = n;
    return 0;
}

static int json_value(const char *begin, const char *end, const char *key,
                      char *out, size_t cap) {
    char needle[96];
    int n = snprintf(needle, sizeof needle, "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof needle) return -1;
    const char *p = begin;
    while (p < end && (p = strstr(p, needle)) != NULL && p < end) {
        p += n;
        while (p < end && isspace((unsigned char)*p)) ++p;
        if (p >= end || *p++ != ':') continue;
        while (p < end && isspace((unsigned char)*p)) ++p;
        if (p >= end || *p++ != '\"') continue;
        size_t w = 0;
        while (p < end && *p != '\"') {
            if (w + 1 >= cap) return -1;
            /* Gson emits '=' as either '=' or the escaped sequence \u003d. */
            if (p + 5 < end && p[0] == '\\' && p[1] == 'u' &&
                p[2] == '0' && p[3] == '0' && p[4] == '3' && p[5] == 'd') {
                out[w++] = '='; p += 6;
            } else {
                out[w++] = *p++;
            }
        }
        if (p >= end) return -1;
        out[w] = '\0';
        return 0;
    }
    return -1;
}

static int json_uint(const char *begin, const char *end, const char *key,
                     uint32_t *out) {
    char value[32];
    if (json_value(begin, end, key, value, sizeof value) == 0) {
        *out = (uint32_t)strtoul(value, NULL, 10);
        return 0;
    }
    char needle[96];
    int n = snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *p = strstr(begin, needle);
    if (!p || p >= end) return -1;
    p += n;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':')) ++p;
    char *q = NULL;
    unsigned long v = strtoul(p, &q, 10);
    if (q == p || q > end) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int decode_field(const char *begin, const char *end, const char *key,
                        uint8_t *out, size_t cap, size_t *len) {
    char text[768];
    if (json_value(begin, end, key, text, sizeof text) != 0) return -1;
    return pifido_base64_decode(text, out, cap, len);
}

int pifido_store_load(const char *path, struct pifido_store *store) {
    memset(store, 0, sizeof *store);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long size = ftell(f);
    if (size <= 0 || size > 4 * 1024 * 1024) { fclose(f); return -1; }
    rewind(f);
    char *json = calloc((size_t)size + 1, 1);
    if (!json) { fclose(f); return -1; }
    size_t got = fread(json, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) { free(json); return -1; }

    const char *p = strstr(json, "\"credentials\"");
    if (!p) { free(json); return 0; }
    p = strchr(p, '[');
    if (!p) { free(json); return -1; }
    while (store->count < PIFIDO_MAX_CREDENTIALS &&
           (p = strstr(p, "\"relayingPartyId\"")) != NULL) {
        const char *end = strstr(p + 1, "\"relayingPartyId\"");
        if (!end) end = json + size;
        const char *kp = strstr(p, "\"keyPair\"");
        const char *kp_end = kp ? strchr(kp, '}') : NULL;
        if (!kp || !kp_end || kp_end > end) { free(json); return -1; }
        struct pifido_credential *c = &store->credentials[store->count];
        char text[768];
        if (json_value(p, end, "relayingPartyId", c->rp_id, sizeof c->rp_id) != 0 ||
            decode_field(p, end, "userId", c->user_id, sizeof c->user_id, &c->user_id_len) != 0 ||
            decode_field(p, end, "id", c->credential_id, sizeof c->credential_id, &c->credential_id_len) != 0 ||
            json_value(kp, kp_end, "privateKey", text, sizeof text) != 0 ||
            pifido_base64_decode(text, c->private_key_der, sizeof c->private_key_der, &c->private_key_der_len) != 0 ||
            json_value(kp, kp_end, "publicKey", text, sizeof text) != 0 ||
            pifido_base64_decode(text, c->public_key_der, sizeof c->public_key_der, &c->public_key_der_len) != 0 ||
            json_uint(p, end, "signatureCount", &c->signature_count) != 0) {
            free(json);
            return -1;
        }
        ++store->count;
        p = end;
    }
    free(json);
    return 0;
}

int pifido_store_increment_counter(const char *path, const uint8_t *credential_id,
                                   size_t credential_id_len, uint32_t *new_count) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long size = ftell(f);
    if (size <= 0 || size > 4 * 1024 * 1024) { fclose(f); return -1; }
    rewind(f);
    char *json = calloc((size_t)size + 1, 1);
    if (!json) { fclose(f); return -1; }
    size_t got = fread(json, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) { free(json); return -1; }

    char encoded[128];
    if (!pifido_base64_encode(credential_id, credential_id_len, encoded, sizeof encoded)) { free(json); return -1; }
    char escaped[256];
    size_t ew = 0;
    for (size_t i = 0; encoded[i] && ew + 6 < sizeof escaped; ++i) {
        if (encoded[i] == '=') {
            memcpy(escaped + ew, "\\u003d", 6); ew += 6;
        } else escaped[ew++] = encoded[i];
    }
    escaped[ew] = '\0';
    char needle[320];
    snprintf(needle, sizeof needle, "\"id\": \"%s\"", encoded);
    char *id = strstr(json, needle);
    if (!id) {
        snprintf(needle, sizeof needle, "\"id\": \"%s\"", escaped);
        id = strstr(json, needle);
    }
    if (!id) { free(json); return -1; }
    char *counter = NULL;
    for (char *scan = strstr(json, "\"signatureCount\"");
         scan && scan < id; scan = strstr(scan + 1, "\"signatureCount\""))
        counter = scan;
    if (!counter) { free(json); return -1; }
    counter = strchr(counter, ':');
    if (!counter) { free(json); return -1; }
    ++counter;
    while (*counter == ' ' || *counter == '\t') ++counter;
    char *end = NULL;
    unsigned long old = strtoul(counter, &end, 10);
    if (end == counter || old >= UINT32_MAX) { free(json); return -1; }
    char replacement[32];
    int replacement_len = snprintf(replacement, sizeof replacement, "%lu", old + 1);
    size_t tail_len = strlen(end);
    size_t prefix_len = (size_t)(counter - json);
    size_t new_len = prefix_len + (size_t)replacement_len + tail_len;
    char *updated = malloc(new_len + 1);
    if (!updated) { free(json); return -1; }
    memcpy(updated, json, prefix_len);
    memcpy(updated + prefix_len, replacement, (size_t)replacement_len);
    memcpy(updated + prefix_len + replacement_len, end, tail_len + 1);

    char temp_path[4096];
    int path_len = snprintf(temp_path, sizeof temp_path, "%s.tmp.%ld", path, (long)getpid());
    if (path_len < 0 || (size_t)path_len >= sizeof temp_path) { free(updated); free(json); return -1; }
    int fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { free(updated); free(json); return -1; }
    int rc = 0;
    if (write(fd, updated, new_len) != (ssize_t)new_len || fsync(fd) != 0) rc = -1;
    if (close(fd) != 0) rc = -1;
    if (rc == 0 && rename(temp_path, path) != 0) rc = -1;
    if (rc == 0) {
        char directory[4096];
        const char *slash = strrchr(path, '/');
        size_t dlen = slash ? (size_t)(slash - path) : 1;
        if (dlen >= sizeof directory) rc = -1;
        else {
            if (slash) memcpy(directory, path, dlen); else directory[0] = '.';
            directory[dlen] = '\0';
            int dfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dfd < 0 || fsync(dfd) != 0) rc = -1;
            if (dfd >= 0) close(dfd);
        }
    }
    if (rc != 0) unlink(temp_path);
    if (new_count) *new_count = (uint32_t)(old + 1);
    free(updated);
    free(json);
    return rc;
}

static size_t escape_b64(const uint8_t *data, size_t len, char *out, size_t cap) {
    char encoded[1024];
    if (!pifido_base64_encode(data, len, encoded, sizeof encoded)) return 0;
    size_t w = 0;
    for (size_t i = 0; encoded[i]; ++i) {
        if (encoded[i] == '=') {
            if (w + 6 >= cap) return 0;
            memcpy(out + w, "\\u003d", 6); w += 6;
        } else {
            if (w + 1 >= cap) return 0;
            out[w++] = encoded[i];
        }
    }
    out[w] = '\0';
    return w;
}

static int atomic_write_json(const char *path, const char *data, size_t len) {
    char temp_path[4096];
    int n = snprintf(temp_path, sizeof temp_path, "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof temp_path) return -1;
    int fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int rc = 0;
    if (write(fd, data, len) != (ssize_t)len || fsync(fd) != 0) rc = -1;
    if (close(fd) != 0) rc = -1;
    if (rc == 0 && rename(temp_path, path) != 0) rc = -1;
    if (rc == 0) {
        char directory[4096]; const char *slash = strrchr(path, '/');
        size_t dlen = slash ? (size_t)(slash - path) : 1;
        if (dlen >= sizeof directory) rc = -1;
        else {
            if (slash) memcpy(directory, path, dlen); else directory[0] = '.';
            directory[dlen] = '\0';
            int dfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dfd < 0 || fsync(dfd) != 0) rc = -1;
            if (dfd >= 0) close(dfd);
        }
    }
    if (rc != 0) unlink(temp_path);
    return rc;
}

int pifido_store_add_credential(const char *path, const char *rp_id,
                                const uint8_t *user_id, size_t user_id_len,
                                const uint8_t *credential_id, size_t credential_id_len,
                                const uint8_t *private_key_der, size_t private_key_der_len,
                                const uint8_t *public_key_der, size_t public_key_der_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long size = ftell(f); if (size <= 0 || size > 4 * 1024 * 1024) { fclose(f); return -1; }
    rewind(f);
    char *json = calloc((size_t)size + 1, 1); if (!json) { fclose(f); return -1; }
    size_t got = fread(json, 1, (size_t)size, f); fclose(f);
    if (got != (size_t)size) { free(json); return -1; }
    char user[1024] = "", id[1024], priv[2048], pub[2048];
    /* An empty userId is valid for the Java U2F compatibility path. */
    if ((user_id_len && !escape_b64(user_id, user_id_len, user, sizeof user)) ||
        !escape_b64(credential_id, credential_id_len, id, sizeof id) ||
        !escape_b64(private_key_der, private_key_der_len, priv, sizeof priv) ||
        !escape_b64(public_key_der, public_key_der_len, pub, sizeof pub)) { free(json); return -1; }
    const char *marker = strstr(json, "\"credentials\"");
    const char *open = marker ? strchr(marker, '[') : NULL;
    const char *close = open ? strchr(open, ']') : NULL;
    if (!open || !close) { free(json); return -1; }
    int has_existing = 0;
    for (const char *q = open + 1; q < close; ++q) if (!isspace((unsigned char)*q)) { has_existing = 1; break; }
    char item[8192];
    int item_len = snprintf(item, sizeof item,
        "%s{\n      \"relayingPartyId\": \"%s\",\n      \"creation\": 0,\n      \"userId\": \"%s\",\n      \"keyPair\": {\n        \"namedCurve\": \"P256_ECDSA\",\n        \"publicKey\": \"%s\",\n        \"privateKey\": \"%s\"\n      },\n      \"signatureCount\": 0,\n      \"id\": \"%s\"\n    }",
        has_existing ? ",\n    " : "", rp_id, user, pub, priv, id);
    if (item_len < 0 || (size_t)item_len >= sizeof item) { free(json); return -1; }
    size_t prefix = (size_t)(close - json), suffix = strlen(close);
    char *updated = malloc((size_t)size + (size_t)item_len + 1);
    if (!updated) { free(json); return -1; }
    memcpy(updated, json, prefix); memcpy(updated + prefix, item, (size_t)item_len);
    memcpy(updated + prefix + item_len, close, suffix + 1);
    int rc = atomic_write_json(path, updated, prefix + (size_t)item_len + suffix);
    free(updated); free(json); return rc;
}

int pifido_store_delete_credential(const char *path, const uint8_t *credential_id,
                                   size_t credential_id_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long size = ftell(f);
    if (size <= 0 || size > 4 * 1024 * 1024) { fclose(f); return -1; }
    rewind(f);
    char *json = calloc((size_t)size + 1, 1);
    if (!json) { fclose(f); return -1; }
    size_t got = fread(json, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) { free(json); return -1; }

    char encoded[256];
    if (!pifido_base64_encode(credential_id, credential_id_len,
                               encoded, sizeof encoded)) {
        free(json); return -1;
    }
    char needle[320];
    int n = snprintf(needle, sizeof needle, "\"id\": \"%s\"", encoded);
    char *id = n > 0 && (size_t)n < sizeof needle ? strstr(json, needle) : NULL;
    if (!id) {
        /* JSON writer escapes base64 padding as \\u003d. */
        char escaped[320]; size_t w = 0;
        for (size_t i = 0; encoded[i] && w + 6 < sizeof escaped; ++i) {
            if (encoded[i] == '=') { memcpy(escaped + w, "\\u003d", 6); w += 6; }
            else escaped[w++] = encoded[i];
        }
        escaped[w] = '\0';
        n = snprintf(needle, sizeof needle, "\"id\": \"%s\"", escaped);
        id = n > 0 && (size_t)n < sizeof needle ? strstr(json, needle) : NULL;
    }
    if (!id) { free(json); return 1; }

    /* Credential objects are emitted with a four-space closing delimiter;
     * locate that delimiter rather than the nested keyPair closing brace. */
    char *start = NULL;
    for (char *scan = json; ; ) {
        char *candidate = strstr(scan, "\n    {");
        if (!candidate || candidate >= id) break;
        start = candidate + 1;
        scan = candidate + 1;
    }
    if (!start) {
        start = strchr(json, '{');
        if (!start || start >= id) { free(json); return -1; }
    }
    char *end = strstr(id, "\n    }");
    if (!end) { free(json); return -1; }
    end += strlen("\n    }");
    while (*end == ' ' || *end == '\n' || *end == '\r' || *end == ',') ++end;
    if (*end == ',') ++end;
    while (*end == ' ' || *end == '\n' || *end == '\r') ++end;
    size_t prefix_len = (size_t)(start - json);
    size_t suffix_len = (size_t)size - (size_t)(end - json);
    char *updated = malloc(prefix_len + suffix_len + 1);
    if (!updated) { free(json); return -1; }
    memcpy(updated, json, prefix_len);
    memcpy(updated + prefix_len, end, suffix_len);
    updated[prefix_len + suffix_len] = '\0';
    int rc = atomic_write_json(path, updated, prefix_len + suffix_len);
    free(updated); free(json);
    return rc;
}
