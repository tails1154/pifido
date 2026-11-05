CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

.PHONY: all clean test

all: pifido-native

pifido-native: pifido_native.c store.c store.h
	$(CC) $(CFLAGS) -o $@ pifido_native.c store.c

test: pifido-native store-test
	./pifido-native --self-test
	./store-test

store-test: store_test.c store.c store.h
	$(CC) $(CFLAGS) -o $@ store_test.c store.c

clean:
	rm -f pifido-native store-test
