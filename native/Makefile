CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

.PHONY: all clean test

all: pifido-native

CRYPTO_LIBS ?= -lcrypto -lmbedcrypto

pifido-native: pifido_native.c store.c crypto.c cbor.c ctap.c store.h crypto.h cbor.h ctap.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ pifido_native.c store.c crypto.c cbor.c ctap.c $(CRYPTO_LIBS)

test: pifido-native store-test
	./pifido-native --self-test
	./pifido-native --check-store test_credentials.json
	./store-test

store-test: store_test.c store.c crypto.c cbor.c ctap.c store.h crypto.h cbor.h ctap.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ store_test.c store.c crypto.c cbor.c ctap.c $(CRYPTO_LIBS)

clean:
	rm -f pifido-native store-test
