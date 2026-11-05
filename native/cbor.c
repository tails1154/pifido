#include "cbor.h"

static int head(struct cbor_reader *r, uint8_t *major, uint64_t *arg) {
    if (r->pos >= r->len) return -1;
    uint8_t b = r->data[r->pos++];
    *major = b >> 5;
    uint8_t ai = b & 31;
    if (ai < 24) { *arg = ai; return 0; }
    size_t n = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : ai == 27 ? 8 : 0;
    if (!n || r->len - r->pos < n) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | r->data[r->pos++];
    *arg = v;
    return 0;
}

int cbor_read_uint(struct cbor_reader *r, uint64_t *v) {
    uint8_t major; if (head(r, &major, v) != 0 || major != 0) return -1; return 0;
}
int cbor_read_bytes(struct cbor_reader *r, const uint8_t **p, size_t *n) {
    uint8_t major; uint64_t len;
    if (head(r, &major, &len) != 0 || major != 2 || len > r->len - r->pos) return -1;
    *p = r->data + r->pos; *n = (size_t)len; r->pos += (size_t)len; return 0;
}
int cbor_read_text(struct cbor_reader *r, const char **p, size_t *n) {
    uint8_t major; uint64_t len;
    if (head(r, &major, &len) != 0 || major != 3 || len > r->len - r->pos) return -1;
    *p = (const char *)(r->data + r->pos); *n = (size_t)len; r->pos += (size_t)len; return 0;
}
int cbor_read_map_len(struct cbor_reader *r, size_t *n) {
    uint8_t major; uint64_t v; if (head(r, &major, &v) != 0 || major != 5 || v > SIZE_MAX) return -1; *n = (size_t)v; return 0;
}
int cbor_read_array_len(struct cbor_reader *r, size_t *n) {
    uint8_t major; uint64_t v; if (head(r, &major, &v) != 0 || major != 4 || v > SIZE_MAX) return -1; *n = (size_t)v; return 0;
}
int cbor_skip(struct cbor_reader *r) {
    uint8_t major; uint64_t n;
    if (head(r, &major, &n) != 0) return -1;
    if (major == 0 || major == 1) return 0;
    if (major == 2 || major == 3) { if (n > r->len - r->pos) return -1; r->pos += (size_t)n; return 0; }
    if (major == 4) {
        for (uint64_t i = 0; i < n; ++i) if (cbor_skip(r) != 0) return -1;
        return 0;
    }
    if (major == 5) {
        for (uint64_t i = 0; i < n * 2; ++i) if (cbor_skip(r) != 0) return -1;
        return 0;
    }
    return -1;
}

static int put(struct cbor_writer *w, uint8_t b) { if (w->pos >= w->cap) return -1; w->data[w->pos++] = b; return 0; }
static int write_head(struct cbor_writer *w, uint8_t major, uint64_t v) {
    if (v < 24) return put(w, (uint8_t)((major << 5) | v));
    size_t n = v <= 0xff ? 1 : v <= 0xffff ? 2 : v <= 0xffffffffu ? 4 : 8;
    if (put(w, (uint8_t)((major << 5) | (n == 1 ? 24 : n == 2 ? 25 : n == 4 ? 26 : 27))) != 0) return -1;
    for (size_t i = n; i; --i) if (put(w, (uint8_t)(v >> ((i - 1) * 8))) != 0) return -1;
    return 0;
}
int cbor_write_uint(struct cbor_writer *w, uint64_t v) { return write_head(w, 0, v); }
int cbor_write_bytes(struct cbor_writer *w, const uint8_t *p, size_t n) { if (write_head(w, 2, n) != 0 || w->cap - w->pos < n) return -1; for (size_t i=0;i<n;++i) w->data[w->pos++]=p[i]; return 0; }
int cbor_write_text(struct cbor_writer *w, const char *p, size_t n) { if (write_head(w, 3, n) != 0 || w->cap - w->pos < n) return -1; for (size_t i=0;i<n;++i) w->data[w->pos++]=(uint8_t)p[i]; return 0; }
int cbor_write_map_len(struct cbor_writer *w, size_t n) { return write_head(w, 5, n); }
int cbor_write_array_len(struct cbor_writer *w, size_t n) { return write_head(w, 4, n); }
