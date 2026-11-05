CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

.PHONY: all clean test

all: pifido-native

pifido-native: pifido_native.c
	$(CC) $(CFLAGS) -o $@ $<

test: pifido-native
	./pifido-native --self-test

clean:
	rm -f pifido-native
