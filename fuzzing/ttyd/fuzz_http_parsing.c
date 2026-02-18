/*
 * AFL++ / LibFuzzer harness — TTYD HTTP callback (full request handling)
 *
 * Target: the real callback_http() from ttyd's http.c
 * Technique: #include the source file directly so static functions are
 *            accessible (standard OSS-Fuzz approach).
 *
 * Exercises: check_auth(), access_log(), path routing (/token, /index,
 *            parent redirect, 404), accept_gzip(), uncompress_html(),
 *            LWS_CALLBACK_HTTP_WRITEABLE response path.
 *
 * Input format (structured binary — pairs with http_mutator.so):
 *   [auth_mode:1][cred_len:2 BE][credential][path_len:2 BE][path][auth_header_value]
 *
 *   auth_mode 0 — no auth required
 *   auth_mode 1 — Basic auth  (credential = expected base64 value)
 *   auth_mode 2 — custom header auth (X-Auth-User)
 *
 * Build (handled by build_fuzzers.sh):
 *   afl-clang-fast -fsanitize=address,undefined -g -O1
 *     -I fuzz-include -I ttyd-src/src
 *     fuzz_http_parsing.c
 *     ttyd-obj/{utils,fuzz_lws_mock,mock_server_globals,mock_pty_stubs}.o
 *     -ljson-c -lz -o fuzz_http_parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Mock lws control state — must come before including the real ttyd source */
#include "fuzz_lws_mock.h"

/* Pull in the real ttyd HTTP handler (callback_http, check_auth, etc.) */
#include "ttyd-src/src/http.c"

/* Provided by mock_server_globals.c */
extern struct server  _fuzz_server;
extern void           fuzz_server_reset(void);

/* ── fuzz target ─────────────────────────────────────────────────────────── */

int fuzz_target(const uint8_t *data, size_t size) {
    /* Need at least: auth_mode(1) + cred_len(2) + path_len(2) = 5 bytes */
    if (size < 5) return 0;

    /* Parse structured input */
    uint8_t  auth_mode = data[0] % 3;
    uint16_t cred_len  = (uint16_t)((data[1] << 8) | data[2]);
    if ((size_t)cred_len > size - 5) cred_len = (uint16_t)(size - 5);

    size_t off = 3 + cred_len;
    if (off + 2 > size) return 0;

    uint16_t path_len = (uint16_t)((data[off] << 8) | data[off + 1]);
    off += 2;
    if ((size_t)path_len > size - off) path_len = (uint16_t)(size - off);

    /* Reset all fuzzer-controlled state */
    fuzz_lws_reset();
    fuzz_server_reset();

    /* Set up the credential the server expects */
    static char cred_buf[65536];
    if (auth_mode == 1 && cred_len > 0) {
        memcpy(cred_buf, data + 3, cred_len);
        cred_buf[cred_len] = '\0';
        _fuzz_server.credential  = cred_buf;
        _fuzz_server.auth_header = NULL;
    } else if (auth_mode == 2) {
        _fuzz_server.credential  = NULL;
        _fuzz_server.auth_header = (char *)"X-Auth-User";
    }
    /* auth_mode 0: no auth, both remain NULL */

    /* Extract the URL path (null-terminated for callback_http) */
    static char path_buf[4096];
    int n = path_len < (int)sizeof(path_buf) - 1 ? path_len : (int)sizeof(path_buf) - 1;
    memcpy(path_buf, data + off, n);
    path_buf[n] = '\0';
    off += path_len;

    /* Remaining bytes are the Authorization header value */
    size_t auth_len = (off < size) ? size - off : 0;
    fuzz_lws_set_auth((const char *)(data + off), (int)auth_len);

    /* For custom-header mode, same bytes go to the custom header mock */
    if (auth_mode == 2)
        fuzz_lws_set_custom((const char *)(data + off), (int)auth_len);

    /* ── Exercise the REAL callback_http() ────────────────────────────── */
    struct lws      mock_wsi = {0};
    struct pss_http pss      = {0};

    /* LWS_CALLBACK_HTTP: main request handling (auth, path routing, etc.) */
    int ret = callback_http(&mock_wsi, LWS_CALLBACK_HTTP,
                            &pss, path_buf, (size_t)n);

    /* LWS_CALLBACK_HTTP_WRITEABLE: exercise response body transmission
     * (only meaningful if the HTTP handler set up a buffer) */
    if (ret == 0 && pss.buffer != NULL && pss.len > 0) {
        (void)callback_http(&mock_wsi, LWS_CALLBACK_HTTP_WRITEABLE,
                            &pss, NULL, 0);
    }

    /* Clean up any strdup'd buffer from /token path */
    if (pss.buffer != NULL && pss.buffer != (char *)index_html &&
        pss.buffer != html_cache) {
        free(pss.buffer);
    }

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
