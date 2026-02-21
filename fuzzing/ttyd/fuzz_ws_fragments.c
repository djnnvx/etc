/*
 * AFL++ / LibFuzzer harness — WebSocket fragmented message accumulation
 *
 * Target: callback_tty RECEIVE path, protocol.c:284-293
 *
 *   if (pss->buffer == NULL) {
 *       pss->buffer = xmalloc(len);
 *       pss->len = len;
 *       memcpy(pss->buffer, in, len);
 *   } else {
 *       pss->buffer = xrealloc(pss->buffer, pss->len + len);  <-- integer overflow
 *       memcpy(pss->buffer + pss->len, in, len);
 *       pss->len += len;
 *   }
 *
 * The existing fuzz_websocket_auth harness never reaches the xrealloc branch:
 * lws_is_final_fragment() and lws_remaining_packet_payload() are hardcoded to
 * 1 and 0 respectively, so the early-return at protocol.c:303 is never taken.
 *
 * This harness makes both values fuzzer-controlled so AFL++ can explore:
 *   - Multi-fragment accumulation across N RECEIVE calls
 *   - Integer overflow: pss->len + len → xrealloc(buf, 0) → heap overflow
 *   - Command dispatch on the fully-assembled multi-fragment message
 *
 * Input format:
 *   [num_frags:1]   number of fragments, 1–8 (bottom 3 bits)
 *   [cmd:1]         WebSocket command byte prepended to the first fragment
 *   [payload...]    raw bytes split evenly across fragments
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

int fuzz_target(const uint8_t *data, size_t size) {
    /* need: num_frags(1) + cmd(1) + at least 1 payload byte */
    if (size < 3) return 0;

    int num_frags = (data[0] & 0x07) + 1;   /* 1–8 */
    uint8_t cmd   = data[1];
    const uint8_t *payload = data + 2;
    size_t payload_size    = size - 2;

    /* Build the full virtual message: [cmd][payload...] */
    size_t total = payload_size + 1;
    char *msg = malloc(total);
    if (!msg) return 0;
    msg[0] = (char)cmd;
    memcpy(msg + 1, payload, payload_size);

    fuzz_lws_reset();
    fuzz_server_reset();
    _fuzz_server.writable    = true;
    _fuzz_server.command     = "bash";
    _fuzz_server.prefs_json  = "{}";
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

    /* Burn through the two initial messages + initialization sentinel */
    for (int i = 0; i < 3; i++)
        callback_tty(&mock_wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss, NULL, 0);

    /* Split msg into num_frags fragments and send each as a RECEIVE call */
    size_t frag_size = total / (size_t)num_frags;
    if (frag_size == 0) frag_size = 1;

    size_t off = 0;
    for (int i = 0; i < num_frags && off < total; i++) {
        size_t this_len = (i == num_frags - 1) ? (total - off) : frag_size;
        if (off + this_len > total) this_len = total - off;

        int is_final  = (i == num_frags - 1) ? 1 : 0;
        size_t remaining = is_final ? 0 : (total - off - this_len);

        fuzz_lws_set_fragment(is_final, remaining);
        int ret = callback_tty(&mock_wsi, LWS_CALLBACK_RECEIVE,
                               &pss, msg + off, this_len);
        if (ret != 0) break;
        off += this_len;
    }

cleanup:
    free(msg);
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
