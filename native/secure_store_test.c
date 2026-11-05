#include "secure_store.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *plain = "/tmp/pifido-secure-plain.json";
    const char *enc = "/tmp/pifido-secure-store.bin";
    const char json[] = "{\"credentials\":[]}";
    int fd = open(plain, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, json, sizeof json - 1) != (ssize_t)(sizeof json - 1)) return 1;
    close(fd);
    uint8_t pin[16] = {0x11}, wrong[16] = {0x22};
    if (pifido_secure_store_sync(enc, plain, pin) != 0) return 1;
    if (pifido_secure_store_load(enc, plain, pin) != 0) return 1;
    if (pifido_secure_store_load(enc, plain, wrong) == 0) return 1;
    unlink(plain); unlink(enc);
    puts("encrypted store self-test passed");
    return 0;
}
