CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

.PHONY: all clean test

all: pifido-native

CRYPTO_LIBS ?= -lcrypto -lmbedcrypto

pifido-native: pifido_native.c store.c crypto.c cbor.c ctap.c pin.c u2f.c secure_store.c store.h crypto.h cbor.h ctap.h pin.h u2f.h secure_store.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ pifido_native.c store.c crypto.c cbor.c ctap.c pin.c u2f.c secure_store.c $(CRYPTO_LIBS)

test: pifido-native store-test pin-test u2f-test secure-store-test
	./pifido-native --self-test
	./pifido-native --check-store test_credentials.json
	./store-test
	./pin-test
	./u2f-test
	./secure-store-test

secure-store-test: secure_store_test.c secure_store.c secure_store.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ secure_store_test.c secure_store.c -lcrypto

store-test: store_test.c store.c crypto.c cbor.c ctap.c store.h crypto.h cbor.h ctap.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ store_test.c store.c crypto.c cbor.c ctap.c $(CRYPTO_LIBS)

pin-test: pin_test.c pin.c cbor.c pin.h cbor.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ pin_test.c pin.c cbor.c -lcrypto

u2f-test: u2f_test.c u2f.c store.c crypto.c u2f.h store.h crypto.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ u2f_test.c u2f.c store.c crypto.c -lcrypto -lmbedcrypto

clean:
	rm -f pifido-native store-test pin-test u2f-test secure-store-test
