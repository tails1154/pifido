/*
 * PiFIDO native userspace authenticator.
 *
 * This file deliberately starts with the transport boundary: one process owns
 * the HID endpoint and implements CTAPHID framing.  CTAP command handlers are
 * added behind this boundary; no JVM or second gadget owner is involved.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "store.h"
#include "crypto.h"
#include "ctap.h"
#include "cbor.h"

#define HID_REPORT_SIZE 64
#define CTAPHID_INIT 0x86
#define CTAPHID_PING 0x81
#define CTAPHID_CBOR 0x90
#define CTAPHID_ERROR 0xbf
#define CTAPHID_KEEPALIVE 0xbb
#define CTAPHID_MSG 0x83
#define CTAPHID_ERR_INVALID_CMD 0x01
#define CTAPHID_ERR_INVALID_PAR 0x02
#define CTAPHID_ERR_INVALID_LEN 0x03
#define CTAPHID_ERR_INVALID_SEQ 0x04
#define CTAPHID_ERR_CHANNEL_BUSY 0x06
#define CTAPHID_ERR_INVALID_CHANNEL 0x0b
#define CTAPHID_BROADCAST_CID 0xffffffffu
#define CTAP2_ERR_INVALID_COMMAND 0x01
#define CTAP2_ERR_INVALID_CBOR 0x12
#define CTAP2_ERR_NO_CREDENTIALS 0x2e

static size_t u2f_apdu(uint8_t *out, size_t cap, const uint8_t *apdu, size_t len) {
    /* Keep the legacy CTAPHID_MSG path well-formed.  Chromium may probe a
     * FIDO2 device with U2F VERSION before selecting CTAP2. */
    if (cap < 2) return 0;
    if (len >= 2 && apdu[1] == 0x03) {
        static const uint8_t version[] = {'U','2','F','_','V','2',0x90,0x00};
        if (cap < sizeof version) return 0;
        memcpy(out, version, sizeof version);
        return sizeof version;
    }
    /* Native CTAP2 is the supported registration/authentication path.  A
     * legacy request is rejected with CONDITIONS_NOT_SATISFIED rather than
     * being silently treated as success or mapped to a different protocol. */
    out[0] = 0x69; out[1] = 0x85;
    return 2;
}

struct hid_state {
    uint32_t cid;
    uint8_t command;
    uint16_t expected;
    uint16_t received;
    uint8_t payload[7609];
    uint8_t next_seq;
};

static uint32_t assigned_cid = 0;

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

static uint32_t allocate_cid(void) {
    uint32_t cid = 0;
    if (getrandom(&cid, sizeof cid, 0) != (ssize_t)sizeof cid ||
        cid == 0 || cid == CTAPHID_BROADCAST_CID)
        cid = 0x01020304u;
    return cid;
}

static int write_report(int fd, uint32_t cid, uint8_t cmd,
                        const uint8_t *data, size_t len) {
    uint8_t report[HID_REPORT_SIZE];
    size_t off = 0;
    uint8_t seq = 0;
    if (len > 0xffffu) return -1;
    while (off == 0 || off < len) {
        memset(report, 0, sizeof report);
        put_be32(report, cid);
        if (off == 0) {
            size_t n = len < 57 ? len : 57;
            report[4] = cmd;
            put_be16(report + 5, (uint16_t)len);
            if (n) memcpy(report + 7, data, n);
            off += n;
        } else {
            size_t n = (len - off) < 59 ? (len - off) : 59;
            report[4] = seq++;
            memcpy(report + 5, data + off, n);
            off += n;
        }
        ssize_t n = write(fd, report, sizeof report);
        if (n != (ssize_t)sizeof report) return -1;
    }
    return 0;
}

static size_t get_info(uint8_t *out, size_t cap) {
    /* CTAP2 authenticatorGetInfo response, CBOR map.  Keep the field
     * numbers aligned with the specification: 0x03 is the 16-byte AAGUID,
     * 0x04 is the options map, and 0x05 is maxMsgSize. */
    static const uint8_t info[] = {
        0xa6,
        0x01, 0x81, 0x68, 'F','I','D','O','_','2','_','0',
        0x03, 0x50,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x04, 0xa3,
        0x64, 'p','l','a','t', 0xf4,
        0x62, 'r','k', 0xf5,
        0x62, 'u','p', 0xf5,
        0x05, 0x19, 0x04, 0xb0,
        0x06, 0x81, 0x01,
        0x09, 0x81, 0x63, 'u','s','b'
    };
    if (cap < sizeof info) return 0;
    memcpy(out, info, sizeof info);
    return sizeof info;
}

static int dispatch_cbor(int fd, uint32_t cid, const uint8_t *p, size_t n,
                         struct pifido_store *store, const char *store_path) {
    uint8_t response[256];
    size_t r = 0;
    if (n == 0) { response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
    if (p[0] == 0x04) {
        r = get_info(response + 1, sizeof response - 1);
        if (!r) return -1;
        response[0] = 0;
        return write_report(fd, cid, CTAPHID_CBOR, response, r + 1);
    }
    if (p[0] == 0x02) {
        r = 0;
        if (pifido_get_assertion(p + 1, n - 1, store, store_path,
                                 response + 1, sizeof response - 1, &r) == 0) {
            response[0] = 0;
            return write_report(fd, cid, CTAPHID_CBOR, response, r + 1);
        }
        response[0] = CTAP2_ERR_NO_CREDENTIALS;
        return write_report(fd, cid, CTAPHID_CBOR, response, 1);
    }
    if (p[0] == 0x01) {
        r = 0;
        if (pifido_make_credential(p + 1, n - 1, store, store_path,
                                   response + 1, sizeof response - 1, &r) == 0) {
            response[0] = 0;
            return write_report(fd, cid, CTAPHID_CBOR, response, r + 1);
        }
        response[0] = 0x2e;
        return write_report(fd, cid, CTAPHID_CBOR, response, 1);
    }
    response[0] = CTAP2_ERR_INVALID_COMMAND;
    return write_report(fd, cid, CTAPHID_CBOR, response, 1);
}

static int dispatch_hid(int fd, uint32_t cid, uint8_t command,
                        const uint8_t *p, size_t n, struct pifido_store *store,
                        const char *store_path) {
    uint8_t response[7609];
    if (command == CTAPHID_INIT) {
        if (n != 8) {
            uint8_t e = CTAPHID_ERR_INVALID_LEN;
            return write_report(fd, cid, CTAPHID_ERROR, &e, 1);
        }
        memcpy(response, p, 8);
        assigned_cid = allocate_cid();
        put_be32(response + 8, assigned_cid);
        response[12] = 2; response[13] = 1; response[14] = 0;
        response[15] = 0x04; /* CTAPHID_CAPABILITY_CBOR */
        return write_report(fd, cid, CTAPHID_INIT, response, 16);
    }
    if (command == CTAPHID_PING)
        return write_report(fd, cid, CTAPHID_PING, p, n);
    if (command == CTAPHID_MSG) {
        uint8_t msg[2048];
        size_t m = u2f_apdu(msg, sizeof msg, p, n);
        return m ? write_report(fd, cid, CTAPHID_MSG, msg, m) : -1;
    }
    if (command == CTAPHID_CBOR)
        return dispatch_cbor(fd, cid, p, n, store, store_path);
    {
        uint8_t e = CTAPHID_ERR_INVALID_CMD;
        return write_report(fd, cid, CTAPHID_ERROR, &e, 1);
    }
}

static int self_test(void) {
    uint8_t out[256];
    size_t n = get_info(out, sizeof out);
    return n > 0 && out[0] == 0xa6 && out[1] == 0x01 && out[2] == 0x81;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
        return self_test() ? 0 : 1;
    if (argc == 3 && strcmp(argv[1], "--check-store") == 0) {
        struct pifido_store store;
        if (pifido_store_load(argv[2], &store) != 0) return 1;
        printf("loaded %zu credentials\n", store.count);
        if (store.count) printf("first key lengths: private=%zu public=%zu id=%zu\n",
                                store.credentials[0].private_key_der_len,
                                store.credentials[0].public_key_der_len,
                                store.credentials[0].credential_id_len);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--crypto-test") == 0) {
        struct pifido_store store;
        uint8_t digest[32] = {0};
        uint8_t signature[128];
        size_t signature_len = 0;
        if (pifido_store_load(argv[2], &store) != 0 || store.count == 0)
            return 1;
        int sign_rc = pifido_sign_sha256(&store.credentials[0], digest, signature,
                               sizeof signature, &signature_len);
        if (sign_rc != 0)
            return 1;
        return pifido_verify_sha256(&store.credentials[0], digest, signature,
                                    signature_len) == 0 ? 0 : 1;
    }
    if (argc == 3 && strcmp(argv[1], "--assertion-test") == 0) {
        struct pifido_store store;
        uint8_t request[512], response[1024], hash[32] = {0};
        size_t response_len = 0;
        if (pifido_store_load(argv[2], &store) != 0 || store.count == 0) return 1;
        struct cbor_writer w = { request, sizeof request, 0 };
        struct pifido_credential *c = &store.credentials[0];
        if (cbor_write_map_len(&w, 3) != 0 || cbor_write_uint(&w, 1) != 0 ||
            cbor_write_text(&w, c->rp_id, strlen(c->rp_id)) != 0 ||
            cbor_write_uint(&w, 2) != 0 || cbor_write_bytes(&w, hash, sizeof hash) != 0 ||
            cbor_write_uint(&w, 3) != 0 || cbor_write_array_len(&w, 1) != 0 ||
            cbor_write_map_len(&w, 1) != 0 || cbor_write_uint(&w, 2) != 0 ||
            cbor_write_bytes(&w, c->credential_id, c->credential_id_len) != 0) return 1;
        if (pifido_get_assertion(request, w.pos, &store, argv[2], response,
                                 sizeof response, &response_len) != 0) return 1;
        printf("assertion response %zu bytes\n", response_len);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--make-test") == 0) {
        struct pifido_store store; uint8_t request[512], response[2048], hash[32]={0}, uid[]={9}; size_t response_len=0;
        if (pifido_store_load(argv[2], &store) != 0) return 1;
        struct cbor_writer w={request,sizeof request,0};
        if(cbor_write_map_len(&w,4)||cbor_write_uint(&w,1)||cbor_write_bytes(&w,hash,32)||
           cbor_write_uint(&w,2)||cbor_write_map_len(&w,1)||cbor_write_uint(&w,1)||cbor_write_text(&w,"native.test",11)||
           cbor_write_uint(&w,3)||cbor_write_map_len(&w,1)||cbor_write_uint(&w,1)||cbor_write_bytes(&w,uid,sizeof uid)||
           cbor_write_uint(&w,4)||cbor_write_array_len(&w,1)||cbor_write_map_len(&w,1)||cbor_write_uint(&w,3)||cbor_write_int(&w,-7)) return 1;
        if(pifido_make_credential(request,w.pos,&store,argv[2],response,sizeof response,&response_len)!=0) return 1;
        if(pifido_store_load(argv[2],&store)!=0 || store.count == 0) return 1;
        printf("makeCredential response %zu bytes; credentials=%zu\n", response_len, store.count);
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "--hid") != 0) {
        fprintf(stderr, "usage: %s --hid /dev/hidg0\n", argv[0]);
        return 2;
    }
    int fd = open(argv[2], O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open HID endpoint"); return 1; }
    struct hid_state s = { .cid = CTAPHID_BROADCAST_CID };
    const char *store_path = getenv("PIFIDO_STORE");
    if (!store_path) store_path = "/data/pifido/credentials.json";
    struct pifido_store store;
    if (pifido_store_load(store_path, &store) != 0) memset(&store, 0, sizeof store);
    uint8_t report[HID_REPORT_SIZE];
    for (;;) {
        ssize_t n = read(fd, report, sizeof report);
        if (n != HID_REPORT_SIZE) { if (errno == EINTR) continue; break; }
        uint32_t cid = be32(report);
        uint8_t type = report[4];
        if (type & 0x80) {
            uint16_t len = ((uint16_t)report[5] << 8) | report[6];
            if (len > sizeof s.payload || (cid != s.cid && cid != CTAPHID_BROADCAST_CID)) continue;
            if (cid == CTAPHID_BROADCAST_CID && type == CTAPHID_INIT)
                s.cid = CTAPHID_BROADCAST_CID;
            else if (cid != CTAPHID_BROADCAST_CID)
                s.cid = cid;
            s.command = type;
            s.expected = len;
            s.received = (uint16_t)((len < 57) ? len : 57);
            s.next_seq = 0;
            memcpy(s.payload, report + 7, s.received);
            if (s.received == s.expected)
                (void)dispatch_hid(fd, s.cid, s.command, s.payload, s.received, &store, store_path);
            if (s.command == CTAPHID_INIT && assigned_cid != 0)
                s.cid = assigned_cid;
        } else if (type == s.next_seq && s.received < s.expected) {
            size_t ncopy = s.expected - s.received;
            if (ncopy > 59) ncopy = 59;
            memcpy(s.payload + s.received, report + 5, ncopy);
            s.received += (uint16_t)ncopy;
            s.next_seq++;
            if (s.received == s.expected)
                (void)dispatch_hid(fd, s.cid, s.command, s.payload, s.received, &store, store_path);
        }
    }
    close(fd);
    return 1;
}
