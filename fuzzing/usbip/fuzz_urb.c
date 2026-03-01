/*
 * fuzz_urb.c — USB/IP URB PDU header parsing harness (CVE-2016-3955 class).
 *
 * struct usbip_header is a kernel-internal type (not in userspace UAPI), so
 * its wire layout is defined in usbip_fuzz.h. We receive it via usbip_net_recv()
 * and byte-swap fields manually to exercise the validation paths that the
 * kernel's vhci_rx.c / stub_rx.c would perform.
 *
 * CVE-2016-3955: USBIP_RET_SUBMIT with actual_length > transfer_buffer_length
 * causes a heap overflow in usbip_recv_xbuff() (kernel module).
 *
 * Bug classes: transfer_buffer_length negative / INT_MIN, number_of_packets
 * overflow, actual_length > transfer_buffer_length, ep > 15, bad command type.
 *
 * Input format:
 *   [command:4 BE][seqnum:4 BE][devid:4 BE][direction:4 BE][ep:4 BE]  = 20 bytes
 *   [transfer_flags:4][transfer_buffer_length:4][start_frame:4]        = 12 bytes
 *   [number_of_packets:4][interval:4][setup:8]                         = 16 bytes
 *   [... optional data payload ...]
 */

#include "fuzz-include/usbip_fuzz.h"
#include "usbip-src/libsrc/usbip_common.h"
#include "usbip-src/src/usbip_network.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define FAKE_FD      42
#define MAX_XFER_LEN (1 << 16)  /* 64 KB cap to avoid slow-but-legal allocs */

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < USBIP_PDU_HDR_SIZE)
        return 0;

    uint8_t buf[FUZZ_BUF_MAX];
    size_t n = size < FUZZ_BUF_MAX ? size : FUZZ_BUF_MAX;
    memcpy(buf, data, n);

    /*
     * Clamp transfer_buffer_length (bytes 24-27 in the PDU) so we don't
     * spend time on legal multi-MB allocations. Still allows testing
     * negative values and overflow conditions.
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

    struct usbip_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    if (usbip_net_recv(FAKE_FD, &hdr, sizeof(hdr)) < 0)
        return 0;

    /* Byte-swap base header fields from network order */
    hdr.base.command   = ntohl(hdr.base.command);
    hdr.base.seqnum    = ntohl(hdr.base.seqnum);
    hdr.base.devid     = ntohl(hdr.base.devid);
    hdr.base.direction = ntohl(hdr.base.direction);
    hdr.base.ep        = ntohl(hdr.base.ep);

    uint32_t cmd = hdr.base.command;

    if (cmd == USBIP_CMD_SUBMIT || cmd == USBIP_RET_SUBMIT) {
        /*
         * For submit/return, read the payload indicated by transfer_buffer_length.
         * This exercises the CVE-2016-3955 overflow class.
         */
        int32_t xfer_len = (int32_t)ntohl(
            (uint32_t)hdr.u.cmd_submit.transfer_buffer_length);
        if (xfer_len > 0 && xfer_len <= MAX_XFER_LEN) {
            void *payload = malloc((size_t)xfer_len);
            if (payload) {
                usbip_net_recv(FAKE_FD, payload, (size_t)xfer_len);
                free(payload);
            }
        }
    } else if (cmd == USBIP_CMD_UNLINK || cmd == USBIP_RET_UNLINK) {
        /* Unlink just has a seqnum — already in hdr.u.cmd_unlink.seqnum */
        hdr.u.cmd_unlink.seqnum = ntohl(hdr.u.cmd_unlink.seqnum);
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
