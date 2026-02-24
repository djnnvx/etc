/*
 * fuzz_import.c — USB/IP device import reply parsing harness.
 *
 * Exercises usbip_net_recv_op_import_reply() which parses:
 *   [status:4 BE][usbip_usb_device struct (312 bytes)]
 *
 * Also exercises the 32-byte busid field inside op_import_request via a
 * direct server-side path: feed raw bytes that include the busid, then
 * call usbip_net_send_op_import_request() so the code validates/copies
 * the busid field.
 *
 * Interesting bug classes:
 *   - busid not NUL-terminated (missing null byte in 32-byte field)
 *   - busid containing path-traversal chars (../../../etc/passwd style)
 *   - busid containing format-string tokens (%s %n etc.)
 *   - Malformed usbip_usb_device struct fields
 *
 * Input format:
 *   [32-byte busid, possibly without NUL][status:4 BE][usbip_usb_device bytes]
 *
 * Compile (via build_fuzzers.sh):
 *   afl-clang-fast -fsanitize=address,undefined -g -O1 \
 *     -I fuzz-include -I usbip-src/src -I usbip-src/libsrc \
 *     fuzz_import.c usbip_network.o usbip_common.o mock_syscalls.o \
 *     -Wl,--wrap=recv -Wl,--wrap=send -Wl,--wrap=write \
 *     -o fuzz_import
 */

#include "fuzz-include/usbip_fuzz.h"
#include "usbip-src/src/usbip_network.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FAKE_FD 42
#define MIN_INPUT (SYSFS_BUS_ID_SIZE + 4)  /* busid + status */

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < MIN_INPUT)
        return 0;

    /*
     * Path A: parse the import-reply (server → client direction).
     * The first 4 bytes become the status field; the rest is usbip_usb_device.
     * Feed everything starting at byte SYSFS_BUS_ID_SIZE as the "reply body".
     */
    fuzz_reset(data + SYSFS_BUS_ID_SIZE, size - SYSFS_BUS_ID_SIZE);

    struct usbip_usb_device idev;
    memset(&idev, 0, sizeof(idev));
    usbip_net_recv_op_import_reply(FAKE_FD, &idev);

    /*
     * Path B: exercise the request builder with the busid from input bytes.
     * usbip_net_send_op_import_request copies + validates the busid string.
     */
    char busid[SYSFS_BUS_ID_SIZE];
    memcpy(busid, data, SYSFS_BUS_ID_SIZE);
    /* Don't force NUL-termination — that's the point of this test */

    fuzz_reset(data, size);  /* reset buffer so send mock is happy */
    usbip_net_send_op_import_request(FAKE_FD, busid);

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
