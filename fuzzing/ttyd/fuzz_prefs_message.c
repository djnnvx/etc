/*
 * AFL++ / LibFuzzer harness — send_initial_message() stack overflow
 *
 * Target: protocol.c:26 (SET_WINDOW_TITLE) and protocol.c:29 (SET_PREFERENCES)
 *
 *   unsigned char message[LWS_PRE + 1 + 4096];   // 4129 bytes
 *   unsigned char *p = &message[LWS_PRE];          // 4097 bytes of headroom
 *
 *   SET_WINDOW_TITLE:
 *     n = sprintf((char *)p, "%c%s (%s)", cmd, server->command, hostname);
 *     Overflows when server->command > ~3965 bytes (hostname takes up to 127).
 *
 *   SET_PREFERENCES:
 *     n = sprintf((char *)p, "%c%s", cmd, server->prefs_json);
 *     Overflows when server->prefs_json > 4095 bytes.
 *
 * In real ttyd, both fields are admin-controlled (CLI flags --pref, command
 * argv).  This harness makes them fuzzer-controlled to find the overflow and
 * any downstream UB (wrong return value → unexpected -1 from send_initial_message
 * → lws_close_reason path, etc.).
 *
 * Input format:
 *   [prefs_len:2 BE][prefs_json bytes][cmd_len:2 BE][command bytes]
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

static char prefs_buf[65536];
static char cmd_buf[65536];

int fuzz_target(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    /* Parse prefs_json */
    uint16_t prefs_len = (uint16_t)((data[0] << 8) | data[1]);
    size_t off = 2;
    if (prefs_len > size - off)          prefs_len = (uint16_t)(size - off);
    if (prefs_len > sizeof(prefs_buf)-1) prefs_len = sizeof(prefs_buf) - 1;
    memcpy(prefs_buf, data + off, prefs_len);
    prefs_buf[prefs_len] = '\0';
    off += prefs_len;

    /* Parse command */
    if (off + 2 > size) return 0;
    uint16_t cmd_len = (uint16_t)((data[off] << 8) | data[off + 1]);
    off += 2;
    if (cmd_len > size - off)          cmd_len = (uint16_t)(size - off);
    if (cmd_len > sizeof(cmd_buf) - 1) cmd_len = sizeof(cmd_buf) - 1;
    memcpy(cmd_buf, data + off, cmd_len);
    cmd_buf[cmd_len] = '\0';

    fuzz_lws_reset();
    fuzz_server_reset();
    _fuzz_server.prefs_json = prefs_buf;
    _fuzz_server.command    = cmd_buf;
    strncpy(_fuzz_server.terminal_type, "xterm-256color",
            sizeof(_fuzz_server.terminal_type) - 1);
    fuzz_lws_set_uri_path("/ws", 3);

    struct lws     mock_wsi = {0};
    struct pss_tty pss;
    memset(&pss, 0, sizeof(pss));

    /* FILTER: no auth, no origin — always passes */
    if (callback_tty(&mock_wsi, LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
                     &pss, NULL, 0) != 0)
        goto cleanup;

    if (callback_tty(&mock_wsi, LWS_CALLBACK_ESTABLISHED,
                     &pss, NULL, 0) != 0)
        goto cleanup;

    /*
     * Drive through:
     *   WRITEABLE call 1 → SET_WINDOW_TITLE  (sprintf with server->command)
     *   WRITEABLE call 2 → SET_PREFERENCES   (sprintf with server->prefs_json)
     *   WRITEABLE call 3 → sets initialized=true, calls pty_resume(NULL)
     */
    for (int i = 0; i < 3; i++)
        callback_tty(&mock_wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss, NULL, 0);

cleanup:
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
