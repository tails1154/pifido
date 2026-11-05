#include "store.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    struct pifido_store s;
    int rc = pifido_store_load("test_credentials.json", &s);
    if (rc != 0 || s.count != 1)
        return 1;
    if (s.credentials[0].signature_count != 7 || s.credentials[0].credential_id_len != 1)
        return 1;
    if (s.credentials[0].rp_id[0] != 'e') return 1;
    const char *copy = "/tmp/pifido-native-store-test.json";
    int fd = open(copy, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 1;
    const char fixture[] = "{\"credentials\":[{\"relayingPartyId\": \"example.test\",\"userId\": \"AQ==\",\"keyPair\": {\"publicKey\": \"AQ==\",\"privateKey\": \"Ag==\"},\"signatureCount\": 7,\"id\": \"Aw==\"}]}";
    if (write(fd, fixture, sizeof fixture - 1) != (ssize_t)(sizeof fixture - 1)) return 1;
    close(fd);
    uint8_t uid[] = {4}, new_id[] = {5}, priv[] = {6}, pub[] = {7};
    if (pifido_store_add_credential(copy, "new.example", uid, sizeof uid,
                                    new_id, sizeof new_id, priv, sizeof priv,
                                    pub, sizeof pub) != 0) return 1;
    if (pifido_store_load(copy, &s) != 0 || s.count != 2) return 1;
    uint8_t id[] = {3};
    uint32_t count = 0;
    int inc = pifido_store_increment_counter(copy, id, sizeof id, &count);
    if (inc != 0 || count != 8) return 1;
    int reload = pifido_store_load(copy, &s);
    if (reload != 0 || s.credentials[0].signature_count != 8) return 1;
    if (pifido_store_delete_credential(copy, new_id, sizeof new_id) != 0) return 1;
    if (pifido_store_load(copy, &s) != 0 || s.count != 1) return 1;
    /* Exercise deletion of the remaining/first object, then ensure a new
     * registration can append to the resulting empty array. */
    if (pifido_store_delete_credential(copy, id, sizeof id) != 0) return 1;
    if (pifido_store_load(copy, &s) != 0 || s.count != 0) return 1;
    uint8_t id2[] = {8};
    if (pifido_store_add_credential(copy, "after-delete.test", uid, sizeof uid,
                                    id2, sizeof id2, priv, sizeof priv,
                                    pub, sizeof pub) != 0) return 1;
    if (pifido_store_load(copy, &s) != 0 || s.count != 1) return 1;
    unlink(copy);
    puts("credential store self-test passed");
    return 0;
}
