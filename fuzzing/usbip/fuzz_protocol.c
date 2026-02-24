/*
 * fuzz_protocol.c — USB/IP protocol header routing harness.
 *
 * Exercises usbip_net_recv_op_common() (the first function called on every
 * new connection) which parses the 8-byte op_common header and validates
 * the protocol version + operation code.
 *
 * Input format: raw bytes starting at the op_common header.
 *   [version:2 BE][op_code:2 BE][status:4 BE][... payload ...]
 *
 * Compile (via build_fuzzers.sh):
 *   afl-clang-fast -fsanitize=address,undefined -g -O1 \
 *     -I fuzz-include -I usbip-src/src -I usbip-src/libsrc \
 *     fuzz_protocol.c usbip_network.o usbip_common.o mock_syscalls.o \
 *     -Wl,--wrap=recv -Wl,--wrap=send -Wl,--wrap=write \
 *     -o fuzz_protocol
 */

#include "fuzz-include/usbip_fuzz.h"

/* usbip headers come from the kernel source tree (usbip-src/) */
#include "usbip-src/src/usbip_network.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Fake fd — value ignored by our recv() mock */
#define FAKE_FD 42

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < OP_COMMON_SIZE)
        return 0;

    fuzz_reset(data, size);

    /*
     * op_common {version:u16 BE, code:u16 BE, status:u32 BE}
     * usbip_net_recv_op_common reads exactly 8 bytes via recv().
     */
    struct op_common op;
    memset(&op, 0, sizeof(op));

    int ret = usbip_net_recv_op_common(FAKE_FD, &op);
    if (ret < 0)
        return 0;

    uint16_t code   = ntohs(op.code);
    uint32_t status = ntohl(op.status);
    (void)status;

    /*
     * Route to the appropriate reply-parser based on op code.
     * These functions consume additional bytes from g_fuzz_buf via recv().
     */
    switch (code) {
    case OP_REP_DEVLIST: {
        struct usbip_exported_devices edevs;
        memset(&edevs, 0, sizeof(edevs));
        usbip_net_recv_op_devlist_reply(FAKE_FD, &edevs);
        usbip_exported_devices_free(&edevs);
        break;
    }
    case OP_REP_IMPORT: {
        struct usbip_usb_device idev;
        memset(&idev, 0, sizeof(idev));
        usbip_net_recv_op_import_reply(FAKE_FD, &idev);
        break;
    }
    default:
        /* Unknown op code: no further parsing — tests version/code validation */
        break;
    }

    return 0;
}

/* ── AFL++ persistent mode ──────────────────────────────────────── */
#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_one(buf, len);
    }
    return 0;
}

#else /* libfuzzer fallback */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one(data, size);
}

#endif
