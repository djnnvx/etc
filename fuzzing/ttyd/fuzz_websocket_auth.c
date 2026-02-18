/*
 * AFL++ / LibFuzzer harness — TTYD WebSocket AuthToken + window-size JSON
 *
 * Target: the real parse_window_size() and check_auth() from ttyd's protocol.c
 * Technique: #include the source file so static functions are accessible.
 *
 * Input format: [has_credential:1][credential_len:2 BE][credential][json_message]
 *   has_credential odd  → server->credential is set to the credential bytes
 *   has_credential even → no credential (open server)
 *
 * Build (handled by build_fuzzers.sh):
 *   afl-clang-fast -fsanitize=address,undefined -g -O1
 *     -I fuzz-include -I ttyd-src/src
 *     fuzz_websocket_auth.c
 *     ttyd-obj/{http,protocol,utils,fuzz_lws_mock,mock_server_globals,mock_pty_stubs}.o
 *     -ljson-c -o fuzz_websocket_auth
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>

/* Mock lws control state — must come before the real ttyd source */
#include "fuzz_lws_mock.h"

/* Pull in real ttyd protocol code (parse_window_size, check_auth static fns) */
#include "ttyd-src/src/protocol.c"

/* Provided by mock_server_globals.c */
extern struct server  _fuzz_server;
extern void           fuzz_server_reset(void);

/* ── fuzz target ─────────────────────────────────────────────────────────── */

int fuzz_target(const uint8_t *data, size_t size) {
    if (size < 3) return 0;

    bool     has_credential = (data[0] & 1) == 1;
    uint16_t cred_len       = (uint16_t)((data[1] << 8) | data[2]);
    if ((size_t)cred_len > size - 3) cred_len = (uint16_t)(size - 3);

    fuzz_lws_reset();
    fuzz_server_reset();

    /* Configure server credential */
    static char cred_buf[65536];
    if (has_credential && cred_len > 0) {
        memcpy(cred_buf, data + 3, cred_len);
        cred_buf[cred_len] = '\0';
        _fuzz_server.credential = cred_buf;
    }
    /* lws auth header: supply the same credential bytes so the WS
     * check_auth() path (which uses lws_hdr_copy) can also be explored */
    fuzz_lws_set_auth((const char *)cred_buf, has_credential ? cred_len : 0);

    /* JSON message starts after the credential */
    size_t json_off = 3 + cred_len;
    if (json_off >= size) return 0;

    const char *json_data = (const char *)(data + json_off);
    size_t      json_len  = size - json_off;

    /* Exercise the real parse_window_size() from protocol.c */
    uint16_t cols = 0, rows = 0;
    struct json_object *obj = parse_window_size(json_data, (int)json_len,
                                                &cols, &rows);
    if (!obj) return 0;

    /* Exercise AuthToken validation when credential is configured */
    if (_fuzz_server.credential) {
        struct json_object *tok_obj = NULL;
        if (json_object_object_get_ex(obj, "AuthToken", &tok_obj)) {
            const char *token = json_object_get_string(tok_obj);
            if (token)
                (void)strcmp(token, _fuzz_server.credential);
        }
    }

    /* Also exercise the WS check_auth() static function */
    struct lws      mock_wsi = {0};
    struct pss_tty  pss      = {0};
    (void)check_auth(&mock_wsi, &pss);

    json_object_put(obj);
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
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return fuzz_target(data, size);
}

#ifndef LIBFUZZER
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
