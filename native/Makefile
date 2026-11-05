CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

.PHONY: all clean test

all: pifido-native

MBEDTLS_LIBS ?= -lmbedtls -lmbedcrypto -lmbedx509

pifido-native: pifido_native.c store.c crypto.c store.h crypto.h
	$(CC) $(CFLAGS) -o $@ pifido_native.c store.c crypto.c $(MBEDTLS_LIBS)

test: pifido-native store-test
	./pifido-native --self-test
	./pifido-native --check-store test_credentials.json
	./store-test

store-test: store_test.c store.c crypto.c store.h crypto.h
	$(CC) $(CFLAGS) -o $@ store_test.c store.c crypto.c $(MBEDTLS_LIBS)

clean:
	rm -f pifido-native store-test
