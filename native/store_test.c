#include "store.h"
#include <stdio.h>

int main(void) {
    struct pifido_store s;
    int rc = pifido_store_load("test_credentials.json", &s);
    if (rc != 0 || s.count != 1)
        return 1;
    if (s.credentials[0].signature_count != 7 || s.credentials[0].credential_id_len != 1)
        return 1;
    if (s.credentials[0].rp_id[0] != 'e') return 1;
    puts("credential store self-test passed");
    return 0;
}
