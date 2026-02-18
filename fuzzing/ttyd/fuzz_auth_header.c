/*
 * AFL++ / LibFuzzer harness — TTYD HTTP Authentication Header
 *
 * Target: the real check_auth() function from ttyd's http.c
 * Technique: #include the source file directly so static functions are
 *            accessible (standard OSS-Fuzz approach).
 *
 * Input format: [mode:1][credential_len:2 BE][credential][auth_header_value]
 *   mode 0 — no auth required
 *   mode 1 — Basic auth  (credential = expected base64 value)
 *   mode 2 — custom header auth (X-Auth-User)
 *
 * Build (handled by build_fuzzers.sh):
 *   afl-clang-fast -fsanitize=address,undefined -g -O1
 *     -I fuzz-include -I ttyd-src/src
 *     fuzz_auth_header.c
 *     ttyd-obj/{http,protocol,utils,fuzz_lws_mock,mock_server_globals,mock_pty_stubs}.o
 *     -ljson-c -o fuzz_auth_header
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Mock lws control state — must come before including the real ttyd source */
#include "fuzz_lws_mock.h"

/* Pull in the real ttyd structs (server.h included transitively via http.c) */
/* fuzz-include/libwebsockets.h and fuzz-include/uv.h shadow the real ones   */
#include "ttyd-src/src/http.c"   /* gives us static check_auth() */

/* Provided by mock_server_globals.c */
extern struct server  _fuzz_server;
extern void           fuzz_server_reset(void);

/* ── fuzz target ─────────────────────────────────────────────────────────── */

int fuzz_target(const uint8_t *data, size_t size) {
    if (size < 3) return 0;

    /* Parse structured input */
    uint8_t  mode     = data[0] % 3;
    uint16_t cred_len = (uint16_t)((data[1] << 8) | data[2]);
    if ((size_t)cred_len > size - 3) cred_len = (uint16_t)(size - 3);

    /* Reset fuzzer-controlled lws state and the server global */
    fuzz_lws_reset();
    fuzz_server_reset();

    /* Set up the credential the server expects */
    static char cred_buf[65536];
    if (mode == 1 && cred_len > 0) {
        /* Basic auth: credential bytes become the expected base64 value */
        memcpy(cred_buf, data + 3, cred_len);
        cred_buf[cred_len] = '\0';
        _fuzz_server.credential  = cred_buf;
        _fuzz_server.auth_header = NULL;
    } else if (mode == 2) {
        /* Custom header auth */
        _fuzz_server.credential  = NULL;
        _fuzz_server.auth_header = (char *)"X-Auth-User";
    }
    /* mode 0: no auth, both remain NULL */

    /* Remaining bytes are the inbound Authorization header value that
     * lws_hdr_copy() will return via the mock */
    const uint8_t *auth_data  = data + 3 + cred_len;
    size_t         auth_len   = size - 3 - cred_len;
    fuzz_lws_set_auth((const char *)auth_data, (int)auth_len);

    /* For custom-header mode, same bytes are treated as the custom header */
    if (mode == 2)
        fuzz_lws_set_custom((const char *)auth_data, (int)auth_len);

    /* Call the REAL check_auth() from http.c */
    struct lws      mock_wsi = {0};
    struct pss_http pss      = {0};
    (void)check_auth(&mock_wsi, &pss);

    return 0;
}

/* ── AFL++ persistent mode ───────────────────────────────────────────────── */
#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
int main(void) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        fuzz_target(buf, __AFL_FUZZ_TESTCASE_LEN);
    }
    return 0;
}

#else
/* LibFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return fuzz_target(data, size);
}

#ifndef LIBFUZZER
/* Standalone file-based testing */
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "Usage: %s <input_file>\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, f); fclose(f);
    fuzz_target(buf, sz);
    free(buf);
    return 0;
}
#endif
#endif
