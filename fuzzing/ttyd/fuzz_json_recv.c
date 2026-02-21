/*
 * AFL++ / LibFuzzer harness — RECEIVE command state machine
 *
 * Target: callback_tty RECEIVE handler, protocol.c:307-354
 *
 * The existing fuzz_websocket_auth harness sends exactly one RECEIVE call.
 * This harness sends up to 4 sequential RECEIVE calls, exercising:
 *
 *   Phase 1 (pss->process == NULL):
 *     JSON_DATA ('{') → parse_window_size() + auth token check + spawn_process()
 *     RESIZE_TERMINAL ('1') → parse_window_size(buf+1, len-1) — no process, no-op
 *
 *   Phase 2 (pss->process != NULL, after JSON_DATA):
 *     RESIZE_TERMINAL → parse_window_size(buf+1, len-1) + pty_resize()
 *     INPUT ('0') → pty_write() (mock returns -1 → callback returns -1)
 *     PAUSE ('2') / RESUME ('3') → pty_pause/pty_resume (mock no-ops)
 *
 * Key targets:
 *   - parse_window_size() with arbitrary JSON (json-c attack surface)
 *   - Integer truncation: (uint16_t)json_object_get_int() with extreme values
 *   - State machine transitions across multiple messages
 *   - Buffer management: pss->buffer malloc/free per RECEIVE, no carry-over
 *
 * Input format:
 *   [num_msgs:1]   1–4 messages (bottom 2 bits + 1)
 *   per message:
 *     [cmd:1]          command byte ('0', '1', '2', '3', '{', or other)
 *     [len:2 BE]       payload length (0 is valid but produces len=1 buffer)
 *     [payload...]     raw bytes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <json-c/json.h>

#include "fuzz_lws_mock.h"
#include "ttyd-src/src/protocol.c"

extern struct server _fuzz_server;
extern void          fuzz_server_reset(void);

#define MAX_MSGS 4

int fuzz_target(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    int num_msgs = (data[0] & 0x03) + 1;
    size_t off   = 1;

    struct {
        uint8_t        cmd;
        const uint8_t *payload;
        size_t         len;
    } msgs[MAX_MSGS];
    int parsed = 0;

    for (int i = 0; i < num_msgs && off + 3 <= size; i++) {
        uint8_t  cmd  = data[off++];
        uint16_t plen = (uint16_t)((data[off] << 8) | data[off + 1]);
        off += 2;
        if (plen > size - off) plen = (uint16_t)(size - off);
        msgs[parsed].cmd     = cmd;
        msgs[parsed].payload = data + off;
        msgs[parsed].len     = plen;
        off += plen;
        parsed++;
    }

    if (parsed == 0) return 0;

    fuzz_lws_reset();
    fuzz_server_reset();
    _fuzz_server.writable   = true;
    _fuzz_server.command    = "bash";
    _fuzz_server.prefs_json = "{}";
    strncpy(_fuzz_server.terminal_type, "xterm-256color",
            sizeof(_fuzz_server.terminal_type) - 1);
    fuzz_lws_set_uri_path("/ws", 3);

    struct lws     mock_wsi = {0};
    struct pss_tty pss;
    memset(&pss, 0, sizeof(pss));

    if (callback_tty(&mock_wsi, LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
                     &pss, NULL, 0) != 0)
        goto cleanup;

    if (callback_tty(&mock_wsi, LWS_CALLBACK_ESTABLISHED,
                     &pss, NULL, 0) != 0)
        goto cleanup;

    for (int i = 0; i < 3; i++)
        callback_tty(&mock_wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss, NULL, 0);

    for (int i = 0; i < parsed; i++) {
        /* Full RECEIVE buffer: [cmd_byte][payload...] */
        size_t buf_len = 1 + msgs[i].len;
        char *buf = malloc(buf_len);
        if (!buf) break;
        buf[0] = (char)msgs[i].cmd;
        if (msgs[i].len > 0)
            memcpy(buf + 1, msgs[i].payload, msgs[i].len);

        fuzz_lws_set_fragment(1, 0);
        int ret = callback_tty(&mock_wsi, LWS_CALLBACK_RECEIVE,
                               &pss, buf, buf_len);
        free(buf);

        if (ret != 0) break;
    }

cleanup:
    fuzz_lws_set_fragment(1, 0);
    callback_tty(&mock_wsi, LWS_CALLBACK_CLOSED, &pss, NULL, 0);
    return 0;
}

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
