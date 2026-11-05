#ifndef PIFIDO_CBOR_H
#define PIFIDO_CBOR_H

#include <stddef.h>
#include <stdint.h>

struct cbor_reader { const uint8_t *data; size_t len; size_t pos; };
struct cbor_writer { uint8_t *data; size_t cap; size_t pos; };

int cbor_read_uint(struct cbor_reader *r, uint64_t *v);
int cbor_read_int(struct cbor_reader *r, int64_t *v);
int cbor_read_bytes(struct cbor_reader *r, const uint8_t **p, size_t *n);
int cbor_read_text(struct cbor_reader *r, const char **p, size_t *n);
int cbor_read_map_len(struct cbor_reader *r, size_t *n);
int cbor_read_array_len(struct cbor_reader *r, size_t *n);
int cbor_skip(struct cbor_reader *r);

int cbor_write_uint(struct cbor_writer *w, uint64_t v);
int cbor_write_int(struct cbor_writer *w, int64_t v);
int cbor_write_bytes(struct cbor_writer *w, const uint8_t *p, size_t n);
int cbor_write_text(struct cbor_writer *w, const char *p, size_t n);
int cbor_write_map_len(struct cbor_writer *w, size_t n);
int cbor_write_array_len(struct cbor_writer *w, size_t n);

#endif
