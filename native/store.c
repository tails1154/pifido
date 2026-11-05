#include "store.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
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
