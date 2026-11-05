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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/random.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#include "store.h"
#include "crypto.h"
#include "ctap.h"
#include "cbor.h"
#include "pin.h"
#include "u2f.h"
#include "secure_store.h"

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

static int log_fd = -1;
static int console_fd = -1;
static const uint8_t default_pin_hash[16] = {
    0x06, 0xec, 0x44, 0xcc, 0xee, 0x3b, 0x23, 0xb9,
    0xe0, 0x67, 0xe9, 0x6a, 0xfb, 0x79, 0x6d, 0x3b
};

/* Log transport metadata only. CTAP payloads can contain PIN material,
 * credential IDs, user handles, and clientDataHash values, so payload bytes
 * are deliberately never written to persistent diagnostics. */
static void log_event(const char *format, ...) {
    if (log_fd < 0 && console_fd < 0) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char stamp[32];
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%S", &tm);
    char prefix[48];
    int prefix_len = snprintf(prefix, sizeof prefix, "%s.%03ldZ ", stamp,
                              ts.tv_nsec / 1000000L);
    if (prefix_len < 0) return;
    va_list ap;
    va_start(ap, format);
    if (log_fd >= 0) {
        dprintf(log_fd, "%s", prefix);
        va_list copy;
        va_copy(copy, ap);
        vdprintf(log_fd, format, copy);
        va_end(copy);
        dprintf(log_fd, "\n");
        (void)fdatasync(log_fd);
    }
    if (console_fd >= 0) {
        dprintf(console_fd, "PiFIDO %s", prefix);
        va_list copy;
        va_copy(copy, ap);
        vdprintf(console_fd, format, copy);
        va_end(copy);
        dprintf(console_fd, "\n");
    }
    va_end(ap);
}

static const char *hid_command_name(uint8_t cmd) {
    switch (cmd) {
    case CTAPHID_INIT: return "INIT";
    case CTAPHID_PING: return "PING";
    case CTAPHID_CBOR: return "CBOR";
    case CTAPHID_MSG: return "MSG";
    case CTAPHID_ERROR: return "ERROR";
    case CTAPHID_KEEPALIVE: return "KEEPALIVE";
    default: return "UNKNOWN";
    }
}

static const char *ctap_command_name(const uint8_t *data, size_t len) {
    if (!len) return "empty";
    switch (data[0]) {
    case 0x01: return "makeCredential";
    case 0x02: return "getAssertion";
    case 0x04: return "getInfo";
    case 0x06: return "clientPIN";
    case 0x07: return "reset";
    case 0x08: return "getNextAssertion";
    case 0x09: return "bioEnrollment";
    case 0x0a: return "credentialManagement";
    case 0x0c: return "authenticatorConfig";
    default: return "unknown";
    }
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
static uint8_t device_aaguid[16];

struct credential_management_state {
    int rp_index;
    int credential_index;
    char rp_id[256];
    int active_rp;
    int active_credentials;
};

static struct credential_management_state management_state;

static size_t count_unique_rps(const struct pifido_store *store) {
    size_t count = 0;
    for (size_t i = 0; i < store->count; ++i) {
        int seen = 0;
        for (size_t j = 0; j < i; ++j)
            if (strcmp(store->credentials[i].rp_id, store->credentials[j].rp_id) == 0) seen = 1;
        if (!seen) ++count;
    }
    return count;
}

static int get_rp_at(const struct pifido_store *store, size_t index,
                     char out[256]) {
    size_t seen = 0;
    for (size_t i = 0; i < store->count; ++i) {
        int duplicate = 0;
        for (size_t j = 0; j < i; ++j)
            if (strcmp(store->credentials[i].rp_id, store->credentials[j].rp_id) == 0) duplicate = 1;
        if (!duplicate && seen++ == index) { strcpy(out, store->credentials[i].rp_id); return 0; }
    }
    return -1;
}

static int public_key_cose(const struct pifido_credential *credential,
                           struct cbor_writer *w) {
    const unsigned char *p = credential->public_key_der;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &p, (long)credential->public_key_der_len);
    EC_KEY *ec = key ? EVP_PKEY_get1_EC_KEY(key) : NULL;
    const EC_GROUP *group = ec ? EC_KEY_get0_group(ec) : NULL;
    const EC_POINT *point = ec ? EC_KEY_get0_public_key(ec) : NULL;
    BIGNUM *x = BN_new(), *y = BN_new();
    uint8_t xb[32], yb[32]; int ok = 0;
    if (group && point && x && y && EC_POINT_get_affine_coordinates(group, point, x, y, NULL) == 1 &&
        BN_bn2binpad(x, xb, 32) == 32 && BN_bn2binpad(y, yb, 32) == 32 &&
        cbor_write_map_len(w, 5) == 0 && cbor_write_uint(w, 1) == 0 && cbor_write_uint(w, 2) == 0 &&
        cbor_write_uint(w, 3) == 0 && cbor_write_int(w, -7) == 0 && cbor_write_int(w, -1) == 0 &&
        cbor_write_uint(w, 1) == 0 && cbor_write_int(w, -2) == 0 && cbor_write_bytes(w, xb, 32) == 0 &&
        cbor_write_int(w, -3) == 0 && cbor_write_bytes(w, yb, 32) == 0) ok = 1;
    BN_free(x); BN_free(y); EC_KEY_free(ec); EVP_PKEY_free(key);
    OPENSSL_cleanse(xb, sizeof xb); OPENSSL_cleanse(yb, sizeof yb);
    return ok ? 0 : -1;
}

static int ensure_store_file(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return errno == EEXIST ? 0 : -1;
    static const char empty_store[] = "{\"credentials\":[]}";
    ssize_t written = write(fd, empty_store, sizeof empty_store - 1);
    int ok = written == (ssize_t)(sizeof empty_store - 1) && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok) unlink(path);
    return ok ? 0 : -1;
}

static int load_or_create_aaguid(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        ssize_t n = read(fd, device_aaguid, sizeof device_aaguid);
        close(fd);
        return n == (ssize_t)sizeof device_aaguid ? 0 : -1;
    }
    if (errno != ENOENT || getrandom(device_aaguid, sizeof device_aaguid, 0) != (ssize_t)sizeof device_aaguid)
        return -1;
    char tmp[512];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof tmp) return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int ok = write(fd, device_aaguid, sizeof device_aaguid) == (ssize_t)sizeof device_aaguid && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (ok && rename(tmp, path) != 0) ok = 0;
    if (!ok) unlink(tmp);
    return ok ? 0 : -1;
}

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
        size_t chunk;
        put_be32(report, cid);
        if (off == 0) {
            chunk = len < 57 ? len : 57;
            report[4] = cmd;
            put_be16(report + 5, (uint16_t)len);
            if (chunk) memcpy(report + 7, data, chunk);
            off += chunk;
        } else {
            chunk = (len - off) < 59 ? (len - off) : 59;
            report[4] = seq++;
            memcpy(report + 5, data + off, chunk);
            off += chunk;
        }
        log_event("TX report cid=%08x cmd=%s(0x%02x) seq=%u total=%zu chunk=%zu header=%02x%02x%02x%02x%02x%02x%02x payload=<redacted>",
                  cid, hid_command_name(cmd), cmd, seq ? (unsigned)(seq - 1) : 0,
                  len, chunk, report[0], report[1], report[2], report[3],
                  report[4], report[5], report[6]);
        ssize_t n = write(fd, report, sizeof report);
        if (n != (ssize_t)sizeof report) {
            log_event("TX failure cmd=%s errno=%d (%s)", hid_command_name(cmd), errno, strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* The credential and PIN writers already fsync their temporary file and
 * containing directory. Add a conservative system-wide barrier after every
 * completed HID operation as well, because this device is expected to lose
 * power abruptly. This is intentionally outside the protocol response path:
 * a successful operation has already been made crash-consistent before its
 * response is emitted. */
static void durability_barrier(void) {
    sync();
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
        0x04, 0xa5,
        /* Canonical CBOR map ordering: shorter text keys precede longer
         * keys, then keys are byte-wise lexical. Java's CBOR encoder emits
         * this order and Chromium rejects non-canonical options maps. */
        0x62, 'r','k', 0xf5,
        0x62, 'u','p', 0xf5,
        0x64, 'p','l','a','t', 0xf4,
        0x68, 'c','r','e','d','M','g','m','t', 0xf5,
        /* Match the Java reference's complete PIN capability tuple. This
         * authenticator has a configured PIN and supports protocol 1. */
        0x69, 'c','l','i','e','n','t','P','i','n', 0xf5,
        0x05, 0x19, 0x04, 0xb0,
        0x06, 0x81, 0x01,
        0x09, 0x81, 0x63, 'u','s','b'
    };
    if (cap < sizeof info) return 0;
    memcpy(out, info, sizeof info);
    memcpy(out + 14, device_aaguid, 16);
    return sizeof info;
}

static int dispatch_cbor(int fd, uint32_t cid, const uint8_t *p, size_t n,
                         struct pifido_store *store, const char *store_path,
                         struct pifido_pin_state *pin_state) {
    /* Packed attestation includes the certificate chain and signature, so a
     * registration response is substantially larger than a small CTAP status
     * response. Keep enough room for the full Java-compatible response. */
    uint8_t response[4096];
    const char *encrypted_store = getenv("PIFIDO_STORE_ENCRYPTED");
    if (!encrypted_store) encrypted_store = "/data/pifido/credentials.enc";
    size_t r = 0;
    if (n == 0) { response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
    if (p[0] == 0x04) {
        r = get_info(response + 1, sizeof response - 1);
        if (!r) return -1;
        response[0] = 0;
        log_event("CTAP getInfo status=0 response_bytes=%zu", r);
        return write_report(fd, cid, CTAPHID_CBOR, response, r + 1);
    }
    if (p[0] == 0x02) {
        int user_verified = 0;
        uint8_t pin_status = pifido_pin_check_request(pin_state, p[0], p + 1, n - 1,
                                                      &user_verified);
        if (pin_status != 0) {
            log_event("CTAP getAssertion PIN/UV status=0x%02x", pin_status);
            response[0] = pin_status;
            return write_report(fd, cid, CTAPHID_CBOR, response, 1);
        }
        r = 0;
        if (pifido_get_assertion(p + 1, n - 1, store, store_path,
                                 user_verified,
                                 response + 1, sizeof response - 1, &r) == 0) {
            response[0] = 0;
            log_event("CTAP getAssertion status=0 response_bytes=%zu", r);
            return write_report(fd, cid, CTAPHID_CBOR, response, r + 1);
        }
        response[0] = CTAP2_ERR_NO_CREDENTIALS;
        log_event("CTAP getAssertion status=0x%02x", response[0]);
        return write_report(fd, cid, CTAPHID_CBOR, response, 1);
    }
    if (p[0] == 0x01) {
        int user_verified = 0;
        uint8_t pin_status = pifido_pin_check_request(pin_state, p[0], p + 1, n - 1,
                                                      &user_verified);
        if (pin_status != 0) {
            log_event("CTAP makeCredential PIN/UV status=0x%02x", pin_status);
            response[0] = pin_status;
            return write_report(fd, cid, CTAPHID_CBOR, response, 1);
        }
        r = 0;
        int make_rc = pifido_make_credential(p + 1, n - 1, store, store_path, device_aaguid,
                                             user_verified,
                                             response + 1, sizeof response - 1, &r);
        if (make_rc == 0) {
            if (pifido_secure_store_sync(encrypted_store, store_path, pin_state->pin_hash) != 0) {
                response[0] = 0x7f;
                log_event("CTAP makeCredential persistence failure");
                return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            response[0] = 0;
            log_event("CTAP makeCredential status=0 response_bytes=%zu", r);
            return write_report(fd, cid, CTAPHID_CBOR, response, r + 1);
        }
        response[0] = 0x2e;
        log_event("CTAP makeCredential status=0x%02x internal_stage=%d", response[0], -make_rc);
        return write_report(fd, cid, CTAPHID_CBOR, response, 1);
    }
    if (p[0] == 0x06) {
        r = 0;
        response[0] = pifido_client_pin_command(pin_state, p + 1, n - 1,
                                               response + 1, sizeof response - 1, &r);
        log_event("CTAP clientPIN status=0x%02x response_bytes=%zu", response[0], r);
        return write_report(fd, cid, CTAPHID_CBOR, response, r + 1);
    }
    if (p[0] == 0x0a) {
        struct cbor_reader cr = {p + 1, n - 1, 0};
        size_t fields = 0, params_start = 0, params_end = 0;
        uint64_t subcommand = 0, protocol = 0; int have_sub = 0, have_protocol = 0;
        const uint8_t *auth = NULL; size_t auth_len = 0;
        if (cbor_read_map_len(&cr, &fields) != 0 || fields > 8) {
            response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
        }
        for (size_t i = 0; i < fields; ++i) {
            uint64_t key; if (cbor_read_uint(&cr, &key) != 0) {
                response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            if (key == 1) {
                if (cbor_read_uint(&cr, &subcommand) != 0) { response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
                have_sub = 1;
            } else if (key == 2) {
                params_start = cr.pos;
                if (cbor_skip(&cr) != 0) { response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
                params_end = cr.pos;
            } else if (key == 3) {
                if (cbor_read_uint(&cr, &protocol) != 0) { response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
                have_protocol = 1;
            } else if (key == 4) {
                if (cbor_read_bytes(&cr, &auth, &auth_len) != 0) { response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
            } else if (cbor_skip(&cr) != 0) { response[0] = CTAP2_ERR_INVALID_CBOR; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
        }
        if (!have_sub) {
            response[0] = 0x14; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
        }
        /* CTAP credential-management metadata and enumerate-RPs-begin use no
         * subCommandParams.  Only operations that carry a parameter map
         * require one; get-next operations require neither auth nor params. */
        int needs_auth = subcommand == 1 || subcommand == 2 ||
                         subcommand == 4 || subcommand == 6 || subcommand == 7;
        int needs_params = subcommand == 4 || subcommand == 6 || subcommand == 7;
        if (needs_auth && (!have_protocol || !auth ||
                           (needs_params && params_end <= params_start))) {
            response[0] = 0x14; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
        }
        if (subcommand == 3) {
            char rp[256];
            if (!management_state.active_rp || get_rp_at(store, (size_t)management_state.rp_index, rp) != 0) {
                response[0] = 0x2e; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            management_state.rp_index++;
            uint8_t hash[32]; SHA256((const unsigned char *)rp, strlen(rp), hash);
            struct cbor_writer w = {response + 1, sizeof response - 1, 0};
            /* enumerateRPsGetNextRP must omit totalRPs (key 5); Chromium
             * rejects that field on continuation responses. */
            if (cbor_write_map_len(&w, 2) || cbor_write_uint(&w, 3) || cbor_write_map_len(&w, 1) ||
                cbor_write_text(&w, "id", 2) || cbor_write_text(&w, rp, strlen(rp)) ||
                cbor_write_uint(&w, 4) || cbor_write_bytes(&w, hash, sizeof hash)) {
                response[0] = 0x7f; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            response[0] = 0; return write_report(fd, cid, CTAPHID_CBOR, response, w.pos + 1);
        }
        if (subcommand == 5) {
            if (!management_state.active_credentials || management_state.credential_index < 0) {
                response[0] = 0x2e; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            size_t idx = (size_t)management_state.credential_index;
            while (idx < store->count && strcmp(store->credentials[idx].rp_id, management_state.rp_id) != 0) ++idx;
            if (idx >= store->count) { management_state.active_credentials = 0; response[0] = 0x2e; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
            struct pifido_credential *c = &store->credentials[idx];
            /* Legacy U2F credentials have no WebAuthn user handle. Chromium
             * requires a non-empty user.id in credential-management output;
             * use the stable credential ID as a display-only fallback. */
            const uint8_t *user_id = c->user_id_len ? c->user_id : c->credential_id;
            size_t user_id_len = c->user_id_len ? c->user_id_len : c->credential_id_len;
            struct cbor_writer w = {response + 1, sizeof response - 1, 0};
            /* enumerateCredentialsGetNextCredential must omit
             * totalCredentials (key 9); it is only returned by begin. */
            if (cbor_write_map_len(&w, 3) || cbor_write_uint(&w, 6) || cbor_write_map_len(&w, 3) ||
                cbor_write_text(&w, "id", 2) || cbor_write_bytes(&w, user_id, user_id_len) ||
                cbor_write_text(&w, "name", 4) || cbor_write_text(&w, "stored-credential", 17) ||
                cbor_write_text(&w, "displayName", 11) || cbor_write_text(&w, "Stored credential", 17) ||
                cbor_write_uint(&w, 7) || cbor_write_map_len(&w, 2) || cbor_write_text(&w, "id", 2) ||
                cbor_write_bytes(&w, c->credential_id, c->credential_id_len) ||
                cbor_write_text(&w, "type", 4) || cbor_write_text(&w, "public-key", 10) ||
                cbor_write_uint(&w, 8) || public_key_cose(c, &w)) {
                response[0] = 0x7f; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            management_state.credential_index = (int)idx + 1;
            response[0] = 0; return write_report(fd, cid, CTAPHID_CBOR, response, w.pos + 1);
        }
        uint8_t auth_data[1 + 2048];
        if (params_end - params_start > sizeof auth_data - 1) { response[0] = 0x03; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
        auth_data[0] = (uint8_t)subcommand;
        memcpy(auth_data + 1, p + 1 + params_start, params_end - params_start);
        uint8_t pin_status = pifido_pin_verify_auth(pin_state, protocol, auth_data,
                                                    1 + params_end - params_start,
                                                    auth, auth_len);
        if (pin_status != 0) {
            log_event("CTAP credentialManagement subcommand=%llu PIN status=0x%02x",
                      (unsigned long long)subcommand, pin_status);
            response[0] = pin_status; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
        }
        if (subcommand == 1) {
            struct cbor_writer w = {response + 1, sizeof response - 1, 0};
            if (cbor_write_map_len(&w, 2) || cbor_write_uint(&w, 1) || cbor_write_uint(&w, store->count) ||
                cbor_write_uint(&w, 2) || cbor_write_uint(&w, PIFIDO_MAX_CREDENTIALS - store->count)) {
                response[0] = 0x7f; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            response[0] = 0; return write_report(fd, cid, CTAPHID_CBOR, response, w.pos + 1);
        }
        if (subcommand == 2) {
            management_state.rp_index = 0; management_state.active_rp = 1;
            char rp[256];
            if (get_rp_at(store, 0, rp) != 0) { response[0] = 0x2e; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
            uint8_t hash[32]; SHA256((const unsigned char *)rp, strlen(rp), hash);
            struct cbor_writer w = {response + 1, sizeof response - 1, 0};
            if (cbor_write_map_len(&w, 3) || cbor_write_uint(&w, 3) || cbor_write_map_len(&w, 1) ||
                cbor_write_text(&w, "id", 2) || cbor_write_text(&w, rp, strlen(rp)) ||
                cbor_write_uint(&w, 4) || cbor_write_bytes(&w, hash, sizeof hash) ||
                cbor_write_uint(&w, 5) || cbor_write_uint(&w, count_unique_rps(store))) {
                response[0] = 0x7f; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            management_state.rp_index = 1;
            response[0] = 0; return write_report(fd, cid, CTAPHID_CBOR, response, w.pos + 1);
        }
        if (subcommand == 4) {
            struct cbor_reader pr = {p + 1 + params_start, params_end - params_start, 0};
            size_t pn; const uint8_t *rp_hash = NULL; size_t rp_hash_len = 0;
            if (cbor_read_map_len(&pr, &pn) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
            for (size_t i = 0; i < pn; ++i) { uint64_t key; if (cbor_read_uint(&pr, &key) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); } if (key == 1) { if (cbor_read_bytes(&pr, &rp_hash, &rp_hash_len) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); } } else if (cbor_skip(&pr) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); } }
            if (!rp_hash || rp_hash_len != 32) { response[0] = 0x14; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
            management_state.active_credentials = 0;
            for (size_t i = 0; i < store->count; ++i) { uint8_t h[32]; SHA256((const unsigned char *)store->credentials[i].rp_id, strlen(store->credentials[i].rp_id), h); if (memcmp(h, rp_hash, 32) == 0) { strncpy(management_state.rp_id, store->credentials[i].rp_id, sizeof management_state.rp_id - 1); management_state.credential_index = (int)i; management_state.active_credentials = 1; break; } }
            if (!management_state.active_credentials) { response[0] = 0x2e; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
            size_t idx = (size_t)management_state.credential_index;
            struct pifido_credential *c = &store->credentials[idx];
            const uint8_t *user_id = c->user_id_len ? c->user_id : c->credential_id;
            size_t user_id_len = c->user_id_len ? c->user_id_len : c->credential_id_len;
            size_t total = 0; for (size_t i = 0; i < store->count; ++i) if (strcmp(store->credentials[i].rp_id, management_state.rp_id) == 0) ++total;
            struct cbor_writer w = {response + 1, sizeof response - 1, 0};
            if (cbor_write_map_len(&w, 4) || cbor_write_uint(&w, 6) || cbor_write_map_len(&w, 3) ||
                cbor_write_text(&w, "id", 2) || cbor_write_bytes(&w, user_id, user_id_len) ||
                cbor_write_text(&w, "name", 4) || cbor_write_text(&w, "stored-credential", 17) ||
                cbor_write_text(&w, "displayName", 11) || cbor_write_text(&w, "Stored credential", 17) ||
                cbor_write_uint(&w, 7) || cbor_write_map_len(&w, 2) || cbor_write_text(&w, "id", 2) ||
                cbor_write_bytes(&w, c->credential_id, c->credential_id_len) ||
                cbor_write_text(&w, "type", 4) || cbor_write_text(&w, "public-key", 10) ||
                cbor_write_uint(&w, 8) || public_key_cose(c, &w) || cbor_write_uint(&w, 9) ||
                cbor_write_uint(&w, total)) {
                response[0] = 0x7f; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            management_state.credential_index = (int)idx + 1;
            response[0] = 0; return write_report(fd, cid, CTAPHID_CBOR, response, w.pos + 1);
        }
        if (subcommand == 6) {
            struct cbor_reader pr = {p + 1 + params_start, params_end - params_start, 0};
            size_t pn; const uint8_t *credential_id = NULL; size_t credential_id_len = 0;
            if (cbor_read_map_len(&pr, &pn) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
            for (size_t i = 0; i < pn; ++i) {
                uint64_t key; if (cbor_read_uint(&pr, &key) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
                if (key == 2) {
                    size_t dn; if (cbor_read_map_len(&pr, &dn) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
                    for (size_t j = 0; j < dn; ++j) {
                        const char *dk; size_t dkl;
                        if (cbor_read_text(&pr, &dk, &dkl) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
                        if (dkl == 2 && memcmp(dk, "id", 2) == 0) {
                            if (cbor_read_bytes(&pr, &credential_id, &credential_id_len) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
                        } else if (cbor_skip(&pr) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
                    }
                } else if (cbor_skip(&pr) != 0) { response[0] = 0x12; return write_report(fd, cid, CTAPHID_CBOR, response, 1); }
            }
            int delete_rc = credential_id ? pifido_store_delete_credential(store_path, credential_id, credential_id_len) : -1;
            int reload_rc = delete_rc == 0 ? pifido_store_load(store_path, store) : -1;
            if (!credential_id || delete_rc != 0 || reload_rc != 0) {
                log_event("CTAP credentialManagement delete status=0x2e id_len=%zu delete_rc=%d reload_rc=%d",
                          credential_id_len, delete_rc, reload_rc);
                response[0] = 0x2e; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
            }
            log_event("CTAP credentialManagement delete status=0 id_len=%zu", credential_id_len);
            response[0] = 0; return write_report(fd, cid, CTAPHID_CBOR, response, 1);
        }
        response[0] = CTAP2_ERR_INVALID_COMMAND;
        return write_report(fd, cid, CTAPHID_CBOR, response, 1);
    }
    response[0] = CTAP2_ERR_INVALID_COMMAND;
    log_event("CTAP %s unsupported status=0x%02x", ctap_command_name(p, n), response[0]);
    return write_report(fd, cid, CTAPHID_CBOR, response, 1);
}

static int dispatch_hid(int fd, uint32_t cid, uint8_t command,
                        const uint8_t *p, size_t n, struct pifido_store *store,
                        const char *store_path, struct pifido_pin_state *pin_state) {
    uint8_t response[7609];
    if (command == CTAPHID_INIT) {
        if (n != 8) {
            uint8_t e = CTAPHID_ERR_INVALID_LEN;
            return write_report(fd, cid, CTAPHID_ERROR, &e, 1);
        }
        memcpy(response, p, 8);
        assigned_cid = allocate_cid();
        put_be32(response + 8, assigned_cid);
        /* CTAPHID INIT replies are 17 bytes: nonce (8), CID (4), protocol
         * version (1), major/minor/build (3), then capabilities (1).
         * The original Java implementation emits all 17. Sending only 16
         * placed CBOR capability in the build-version field, causing Chrome
         * to terminate immediately after INIT. */
        response[12] = 2;
        response[13] = 0;
        response[14] = 0;
        response[15] = 0;
        /* Preserve the Java implementation's exact capability byte. Its
         * BitSet-based encoder emits 0x06, and Chrome compatibility depends
         * on that historical wire behavior. */
        response[16] = 0x06;
        log_event("CTAPHID INIT response assigned_cid=%08x capabilities=%02x",
                  assigned_cid, response[16]);
        return write_report(fd, cid, CTAPHID_INIT, response, 17);
    }
    if (command == CTAPHID_PING)
        return write_report(fd, cid, CTAPHID_PING, p, n);
    if (command == CTAPHID_MSG) {
        /* Chromium may probe or use the CTAP1/U2F path even after CTAP2
         * getInfo. The Java reference dispatches MSG to U2fHandler and
         * returns a response with the MSG command, not a CTAPHID error. */
        uint8_t u2f_response[2048];
        size_t u2f_len = 0;
        if (n >= 2)
            log_event("CTAPHID MSG U2F APDU ins=0x%02x p1=0x%02x bytes=%zu",
                      p[1], n >= 3 ? p[2] : 0, n);
        if (pifido_u2f_apdu(p, n, store, store_path, u2f_response,
                            sizeof u2f_response, &u2f_len) != 0) {
            uint8_t e = CTAPHID_ERR_INVALID_PAR;
            log_event("CTAPHID MSG U2F handler failure");
            return write_report(fd, cid, CTAPHID_ERROR, &e, 1);
        }
        if (u2f_len >= 2)
            log_event("CTAPHID MSG U2F response bytes=%zu status=0x%02x%02x",
                      u2f_len, u2f_response[u2f_len - 2], u2f_response[u2f_len - 1]);
        else
            log_event("CTAPHID MSG U2F response bytes=%zu", u2f_len);
        /* Safe structural diagnostics for registration responses. Do not log
         * key material, certificates, signatures, or APDU payload bytes. */
        if (n >= 2 && p[1] == 0x01 && u2f_len >= 99) {
            size_t key_handle_len = u2f_response[66];
            size_t cert_offset = 67 + key_handle_len;
            int cert_header_ok = cert_offset < u2f_len - 2 &&
                                 u2f_response[0] == 0x05 &&
                                 u2f_response[1] == 0x04 &&
                                 u2f_response[cert_offset] == 0x30;
            log_event("CTAPHID MSG U2F registration structure reserved=0x%02x pubkey_prefix=0x%02x key_handle_len=%zu cert_offset=%zu cert_header=%s",
                      u2f_response[0], u2f_response[1], key_handle_len,
                      cert_offset, cert_header_ok ? "ok" : "invalid");
            if (cert_header_ok) {
                const unsigned char *cert_cursor = u2f_response + cert_offset;
                X509 *certificate = d2i_X509(NULL, &cert_cursor,
                                              (long)(u2f_len - cert_offset - 2));
                size_t cert_len = certificate ? (size_t)(cert_cursor - (u2f_response + cert_offset)) : 0;
                size_t signature_len = cert_len <= u2f_len - cert_offset - 2
                    ? u2f_len - cert_offset - 2 - cert_len : 0;
                log_event("CTAPHID MSG U2F DER cert_parse=%s cert_bytes=%zu signature_bytes=%zu signature_prefix=0x%02x",
                          certificate ? "ok" : "invalid", cert_len, signature_len,
                          signature_len ? u2f_response[cert_offset + cert_len] : 0);
                X509_free(certificate);
            }
        }
        return write_report(fd, cid, CTAPHID_MSG, u2f_response, u2f_len);
    }
    if (command == CTAPHID_CBOR)
        return dispatch_cbor(fd, cid, p, n, store, store_path, pin_state);
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
        if (pifido_get_assertion(request, w.pos, &store, argv[2], 0, response,
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
        if(pifido_make_credential(request,w.pos,&store,argv[2],device_aaguid,0,response,sizeof response,&response_len)!=0) return 1;
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
    const char *log_path = getenv("PIFIDO_LOG");
    if (!log_path) log_path = "/data/log.log";
    log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_DSYNC, 0600);
    if (log_fd < 0) {
        dprintf(STDERR_FILENO, "cannot open diagnostic log %s: %s\n", log_path, strerror(errno));
    } else {
        (void)fchmod(log_fd, 0600);
    }
    console_fd = open("/dev/console", O_WRONLY | O_CLOEXEC | O_NOCTTY);
    log_event("authenticator started hid=%s", argv[2]);
    struct hid_state s = { .cid = CTAPHID_BROADCAST_CID };
    const char *store_path = getenv("PIFIDO_STORE");
    if (!store_path) store_path = "/run/pifido/credentials.json";
    const char *encrypted_store = getenv("PIFIDO_STORE_ENCRYPTED");
    if (!encrypted_store) encrypted_store = "/data/pifido/credentials.enc";
    (void)mkdir("/run/pifido", 0700);
    struct pifido_pin_state pin_state;
    if (pifido_pin_init(&pin_state, "/data/pifido/pin.bin", default_pin_hash) != 0) {
        log_event("PIN state load/init failed; authenticator stopping");
        close(fd);
        if (log_fd >= 0) close(log_fd);
        if (console_fd >= 0) close(console_fd);
        return 1;
    }
    struct pifido_store store;
    if (access(encrypted_store, F_OK) == 0) {
        if (pifido_secure_store_load(encrypted_store, store_path, pin_state.pin_hash) != 0) {
            log_event("encrypted credential store authentication failed; refusing startup");
            pifido_pin_destroy(&pin_state); close(fd); return 1;
        }
    } else if (errno == ENOENT) {
        if (ensure_store_file(store_path) != 0 ||
            pifido_secure_store_sync(encrypted_store, store_path, pin_state.pin_hash) != 0) {
            log_event("encrypted credential store initialization failed; refusing startup");
            pifido_pin_destroy(&pin_state); close(fd); return 1;
        }
        log_event("initialized fresh encrypted credential store");
    } else {
        log_event("cannot inspect encrypted credential store; refusing startup");
        pifido_pin_destroy(&pin_state); close(fd); return 1;
    }
    if (pifido_store_load(store_path, &store) != 0) {
        memset(&store, 0, sizeof store);
        log_event("volatile credential store load failed; refusing startup");
        pifido_pin_destroy(&pin_state); close(fd); return 1;
    } else {
        log_event("encrypted credential store loaded count=%zu", store.count);
    }
    char aaguid_path[512];
    const char *aaguid_env = getenv("PIFIDO_AAGUID");
    if (aaguid_env) snprintf(aaguid_path, sizeof aaguid_path, "%s", aaguid_env);
    else snprintf(aaguid_path, sizeof aaguid_path, "/data/pifido/aaguid.bin");
    if (load_or_create_aaguid(aaguid_path) != 0) {
        log_event("AAGUID load/create failed path=%s", aaguid_path);
        close(fd);
        return 1;
    }
    log_event("CTAP clientPIN protocol 1 ready; configured=%s retries=%u",
              pin_state.retries ? "yes" : "blocked", pin_state.retries);
    uint8_t report[HID_REPORT_SIZE];
    for (;;) {
        ssize_t n = read(fd, report, sizeof report);
        if (n != HID_REPORT_SIZE) {
            if (errno == EINTR) continue;
            log_event("RX failure bytes=%ld errno=%d (%s)", (long)n, errno, strerror(errno));
            break;
        }
        uint32_t cid = be32(report);
        uint8_t type = report[4];
        if (type & 0x80) {
            uint16_t len = ((uint16_t)report[5] << 8) | report[6];
            log_event("RX initial cid=%08x cmd=%s(0x%02x) declared=%u header=%02x%02x%02x%02x%02x%02x%02x payload=<redacted>",
                      cid, hid_command_name(type), type, len,
                      report[0], report[1], report[2], report[3], report[4], report[5], report[6]);
            if (len > sizeof s.payload || (cid != s.cid && cid != CTAPHID_BROADCAST_CID)) {
                log_event("RX rejected cid=%08x expected_cid=%08x declared=%u", cid, s.cid, len);
                continue;
            }
            if (cid == CTAPHID_BROADCAST_CID && type == CTAPHID_INIT)
                s.cid = CTAPHID_BROADCAST_CID;
            else if (cid != CTAPHID_BROADCAST_CID)
                s.cid = cid;
            s.command = type;
            s.expected = len;
            s.received = (uint16_t)((len < 57) ? len : 57);
            s.next_seq = 0;
            memcpy(s.payload, report + 7, s.received);
            if (s.received == s.expected) {
                log_event("RX complete cid=%08x cmd=%s bytes=%u%s%s", s.cid,
                          hid_command_name(s.command), s.received,
                          s.command == CTAPHID_CBOR ? " ctap=" : "",
                          s.command == CTAPHID_CBOR ? ctap_command_name(s.payload, s.received) : "");
                (void)dispatch_hid(fd, s.cid, s.command, s.payload, s.received, &store, store_path, &pin_state);
                if (pifido_secure_store_sync(encrypted_store, store_path, pin_state.pin_hash) != 0)
                    log_event("encrypted credential store sync failed");
                durability_barrier();
            }
            if (s.command == CTAPHID_INIT && assigned_cid != 0)
                s.cid = assigned_cid;
        } else if (type == s.next_seq && s.received < s.expected) {
            size_t ncopy = s.expected - s.received;
            if (ncopy > 59) ncopy = 59;
            memcpy(s.payload + s.received, report + 5, ncopy);
            log_event("RX continuation cid=%08x seq=%u chunk=%zu header=%02x%02x%02x%02x%02x payload=<redacted>",
                      cid, type, ncopy, report[0], report[1], report[2], report[3], report[4]);
            s.received += (uint16_t)ncopy;
            s.next_seq++;
            if (s.received == s.expected) {
                log_event("RX complete cid=%08x cmd=%s bytes=%u%s%s", s.cid,
                          hid_command_name(s.command), s.received,
                          s.command == CTAPHID_CBOR ? " ctap=" : "",
                          s.command == CTAPHID_CBOR ? ctap_command_name(s.payload, s.received) : "");
                (void)dispatch_hid(fd, s.cid, s.command, s.payload, s.received, &store, store_path, &pin_state);
                if (pifido_secure_store_sync(encrypted_store, store_path, pin_state.pin_hash) != 0)
                    log_event("encrypted credential store sync failed");
                durability_barrier();
            }
        } else {
            log_event("RX invalid continuation cid=%08x seq=%u expected=%u received=%u/%u",
                      cid, type, s.next_seq, s.received, s.expected);
        }
    }
    pifido_pin_destroy(&pin_state);
    close(fd);
    if (console_fd >= 0) close(console_fd);
    return 1;
}
