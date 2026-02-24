/*
 * fuzz_urb.c — USB/IP URB header parsing harness (CVE-2016-3955 class).
 *
 * Exercises usbip_header parsing: the 48-byte compound header composed of
 * usbip_header_basic (20 bytes) + usbip_header_cmd_submit (28 bytes).
 *
 * Target: usbip_net_pack_pdu() and the length validation performed when
 * processing USBIP_CMD_SUBMIT / USBIP_RET_SUBMIT messages.
 *
 * CVE-2016-3955 pattern: USBIP_RET_SUBMIT with actual_length > urb->transfer_buffer_length
 * causes a heap overflow in usbip_recv_xbuff() (kernel module side).
 * The userspace stub_rx.c also processes these fields.
 *
 * Interesting bug classes:
 *   - transfer_buffer_length negative / INT_MIN
 *   - number_of_packets overflow
 *   - actual_length > transfer_buffer_length (CVE-2016-3955 repro class)
 *   - start_frame out of range for ISO transfers
 *   - ep > 15 (invalid endpoint)
 *
 * Input format:
 *   [command:4 BE][seqnum:4 BE][devid:4 BE][direction:4 BE][ep:4 BE]
 *   [transfer_flags:4 BE][transfer_buffer_length:4 BE][start_frame:4 BE]
 *   [number_of_packets:4 BE][interval:4 BE][setup[8]]
 *   [... optional data payload ...]
 *
 * Compile (via build_fuzzers.sh):
 *   afl-clang-fast -fsanitize=address,undefined -g -O1 \
 *     -I fuzz-include -I usbip-src/src -I usbip-src/libsrc \
 *     fuzz_urb.c usbip_network.o usbip_common.o mock_syscalls.o \
 *     -Wl,--wrap=recv -Wl,--wrap=send -Wl,--wrap=write \
 *     -o fuzz_urb
 */

#include "fuzz-include/usbip_fuzz.h"
#include "usbip-src/src/usbip_network.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define FAKE_FD    42
#define HDR_SIZE   48   /* sizeof(usbip_header) */

/*
 * Cap transfer_buffer_length to 64 KB to avoid spending time on legal
 * multi-MB allocations while still testing overflow conditions.
 */
#define MAX_XFER_LEN (1 << 16)

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < HDR_SIZE)
        return 0;

    uint8_t buf[FUZZ_BUF_MAX];
    size_t n = size < FUZZ_BUF_MAX ? size : FUZZ_BUF_MAX;
    memcpy(buf, data, n);

    /*
     * Read transfer_buffer_length from offset 24 (after the 20-byte basic hdr
     * + 4-byte transfer_flags) and clamp it so we don't OOM.
     */
    int32_t tbl_be;
    memcpy(&tbl_be, buf + 24, 4);
    int32_t tbl = (int32_t)ntohl((uint32_t)tbl_be);
    if (tbl > MAX_XFER_LEN) {
        tbl = MAX_XFER_LEN;
        uint32_t clamped = htonl((uint32_t)tbl);
        memcpy(buf + 24, &clamped, 4);
    }

    fuzz_reset(buf, n);

    /*
     * usbip_net_recv_pdu_header parses the full compound header.
     * This exercises all the byte-swap + validation logic.
     */
    struct usbip_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    usbip_net_recv_pdu_header(FAKE_FD, &hdr);

    /*
     * For submit commands, also exercise the data-payload receive path.
     * usbip_net_recv_xbuff reads transfer_buffer_length bytes — this is
     * where CVE-2016-3955 manifested (actual_length > transfer_buffer_length).
     */
    uint32_t cmd = ntohl(hdr.base.command);
    if (cmd == USBIP_CMD_SUBMIT || cmd == USBIP_RET_SUBMIT) {
        int32_t xfer_len = ntohl((uint32_t)hdr.u.cmd_submit.transfer_buffer_length);
        if (xfer_len > 0 && xfer_len <= MAX_XFER_LEN) {
            void *payload = malloc((size_t)xfer_len);
            if (payload) {
                usbip_net_recv(FAKE_FD, payload, (size_t)xfer_len);
                free(payload);
            }
        }
    }

    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        fuzz_one(buf, __AFL_FUZZ_TESTCASE_LEN);
    }
    return 0;
}

#else

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one(data, size);
}

#endif
