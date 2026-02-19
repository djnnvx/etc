/*
 * AFL++ / LibFuzzer harness — TTYD WebSocket protocol (callback_tty)
 *
 * Exercises the full websocket lifecycle: connection filtering, auth,
 * origin checking, message receive (INPUT, RESIZE, JSON_DATA, etc.),
 * writable callbacks, and connection close/cleanup.
 *
 * Input format:
 *   [flags:1][cred_len:2 BE][credential]
 *   [path_len:1][path][origin_len:1][origin][host_len:1][host]
 *   [ws_message...]
 *
 * Flags byte:
 *   bit 0: has credential (Basic auth)
 *   bit 1: has auth_header (custom header proxy auth)
 *   bit 2: check_origin enabled
 *   bit 3: url_arg enabled
 *   bit 4: writable
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>

/* Mock lws control state — must come before the real ttyd source */
#include "fuzz_lws_mock.h"

/* Pull in real ttyd protocol code (callback_tty and all static helpers) */
#include "ttyd-src/src/protocol.c"

/* Provided by mock_server_globals.c */
extern struct server  _fuzz_server;
extern void           fuzz_server_reset(void);

/* ── input parser ──────────────────────────────────────────────────── */

/* Read a 1-byte length-prefixed field from data. Returns bytes consumed. */
static size_t read_field_1(const uint8_t *data, size_t avail,
                           char *out, int *out_len, int max) {
    if (avail < 1) { *out_len = 0; return 0; }
    int flen = data[0];
    if (flen > (int)(avail - 1)) flen = (int)(avail - 1);
    if (flen > max) flen = max;
    memcpy(out, data + 1, flen);
    out[flen] = '\0';
    *out_len = flen;
    return 1 + flen;
}

/* ── fuzz target ───────────────────────────────────────────────────── */

int fuzz_target(const uint8_t *data, size_t size) {
    /* Minimum: flags(1) + cred_len(2) + path_len(1) + origin_len(1) + host_len(1) */
    if (size < 6) return 0;

    /* Parse flags */
    uint8_t flags = data[0];
    bool has_credential  = (flags & 0x01) != 0;
    bool has_auth_header = (flags & 0x02) != 0;
    bool check_origin    = (flags & 0x04) != 0;
    bool url_arg         = (flags & 0x08) != 0;
    bool writable        = (flags & 0x10) != 0;

    /* Parse credential */
    uint16_t cred_len = (uint16_t)((data[1] << 8) | data[2]);
    size_t off = 3;
    if (cred_len > size - off) cred_len = (uint16_t)(size - off);

    static char cred_buf[65536];
    memcpy(cred_buf, data + off, cred_len);
    cred_buf[cred_len] = '\0';
    off += cred_len;

    /* Parse length-prefixed fields: path, origin, host */
    char path_buf[4096], origin_buf[4096], host_buf[4096];
    int path_len = 0, origin_len = 0, host_len = 0;
    size_t n;

    n = read_field_1(data + off, size - off, path_buf, &path_len, 4095);
    off += n;
    n = read_field_1(data + off, size - off, origin_buf, &origin_len, 4095);
    off += n;
    n = read_field_1(data + off, size - off, host_buf, &host_len, 4095);
    off += n;

    /* Remaining bytes = websocket message payload */
    const uint8_t *ws_msg = (off < size) ? data + off : NULL;
    size_t ws_len = (off < size) ? size - off : 0;

    /* ── Reset mock state ─────────────────────────────────────────── */
    fuzz_lws_reset();
    fuzz_server_reset();

    /* Configure server */
    _fuzz_server.writable     = writable;
    _fuzz_server.check_origin = check_origin;
    _fuzz_server.url_arg      = url_arg;
    _fuzz_server.command      = "bash";
    _fuzz_server.prefs_json   = "{}";
    _fuzz_server.terminal_type[0] = '\0';
    strncpy(_fuzz_server.terminal_type, "xterm-256color",
            sizeof(_fuzz_server.terminal_type) - 1);

    if (has_credential && cred_len > 0) {
        _fuzz_server.credential = cred_buf;
    }
    if (has_auth_header) {
        _fuzz_server.auth_header = "X-Auth-User";
        /* Put credential in custom header mock too */
        fuzz_lws_set_custom(cred_buf, cred_len);
    }

    /* Set up fuzzer-controlled headers */
    if (has_credential) {
        fuzz_lws_set_auth(cred_buf, cred_len);
    }
    fuzz_lws_set_uri_path(path_buf, path_len);
    fuzz_lws_set_origin(origin_buf, origin_len);
    fuzz_lws_set_host(host_buf, host_len);

    /* Set up URI args from the ws_msg if url_arg is enabled.
     * We'll stuff "arg=<first 50 bytes of msg>" as a URI arg fragment
     * to exercise the arg-parsing path in ESTABLISHED. */
    if (url_arg && ws_len > 0) {
        int arg_len = ws_len > 50 ? 50 : (int)ws_len;
        char arg_buf[256];
        memcpy(arg_buf, "arg=", 4);
        memcpy(arg_buf + 4, ws_msg, arg_len);
        arg_buf[4 + arg_len] = '\0';
        memcpy(_fuzz_uri_args[0], arg_buf, 4 + arg_len + 1);
        _fuzz_uri_args_len[0] = 4 + arg_len;
        _fuzz_uri_args_count = 1;
    }

    /* ── Simulate WebSocket lifecycle ─────────────────────────────── */
    struct lws      mock_wsi = {0};
    struct pss_tty  pss;
    memset(&pss, 0, sizeof(pss));

    /* Step 1: FILTER_PROTOCOL_CONNECTION (auth + path + origin check) */
    int ret = callback_tty(&mock_wsi, LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
                           &pss, NULL, 0);
    if (ret != 0) goto cleanup;

    /* Step 2: ESTABLISHED (client setup, URL arg parsing) */
    ret = callback_tty(&mock_wsi, LWS_CALLBACK_ESTABLISHED,
                       &pss, NULL, 0);
    if (ret != 0) goto cleanup;

    /* Step 3: SERVER_WRITEABLE (send initial messages) */
    callback_tty(&mock_wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss, NULL, 0);

    /* Step 4: RECEIVE with the fuzz payload */
    if (ws_msg && ws_len > 0) {
        /* Make a mutable copy — callback_tty may modify the buffer via
         * xrealloc on pss->buffer, but the initial 'in' pointer is just read */
        char *msg_copy = malloc(ws_len);
        if (msg_copy) {
            memcpy(msg_copy, ws_msg, ws_len);
            ret = callback_tty(&mock_wsi, LWS_CALLBACK_RECEIVE,
                               &pss, msg_copy, ws_len);
            free(msg_copy);

            /* If RECEIVE succeeded and the command was JSON_DATA,
             * try another WRITEABLE to exercise the post-auth path */
            if (ret == 0) {
                callback_tty(&mock_wsi, LWS_CALLBACK_SERVER_WRITEABLE,
                             &pss, NULL, 0);
            }
        }
    }

cleanup:
    /* Step 5: CLOSED (cleanup buffers, args, etc.)
     * Do NOT override pss.wsi here.  ttyd only sets pss->wsi after a
     * successful pty_spawn + LIST_INSERT_HEAD.  If FILTER rejected the
     * connection, or ESTABLISHED failed (spawn always returns -1 in the
     * mock), pss->wsi is NULL and ttyd's CLOSED handler skips LIST_REMOVE —
     * which is correct, since pss was never inserted.  Forcing pss->wsi
     * non-NULL here would make LIST_REMOVE deref a NULL le_prev and crash,
     * producing harness artifacts rather than real bugs. */
    callback_tty(&mock_wsi, LWS_CALLBACK_CLOSED, &pss, NULL, 0);

    return 0;
}

/* ── AFL++ persistent mode ───────────────────────────────────────────── */
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
