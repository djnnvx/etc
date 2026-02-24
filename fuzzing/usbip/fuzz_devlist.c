/*
 * fuzz_devlist.c — USB/IP device-list reply parsing harness.
 *
 * Directly exercises usbip_net_recv_op_devlist_reply() which parses:
 *   [ndev:4 BE]  followed by ndev × usbip_usb_device + usbip_usb_interface[]
 *
 * Interesting bug classes:
 *   - Large ndev values causing excessive allocations / OOM
 *   - Malformed device structs (wrong size fields)
 *   - Integer overflow in ndev × sizeof(usbip_usb_device)
 *
 * Input format:
 *   [ndev:4 BE][device_0 struct bytes][...][device_N struct bytes]
 *   Each device is followed by bNumInterfaces × usbip_usb_interface structs.
 *
 * Compile (via build_fuzzers.sh):
 *   afl-clang-fast -fsanitize=address,undefined -g -O1 \
 *     -I fuzz-include -I usbip-src/src -I usbip-src/libsrc \
 *     fuzz_devlist.c usbip_network.o usbip_common.o mock_syscalls.o \
 *     -Wl,--wrap=recv -Wl,--wrap=send -Wl,--wrap=write \
 *     -o fuzz_devlist
 */

#include "fuzz-include/usbip_fuzz.h"
#include "usbip-src/src/usbip_network.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define FAKE_FD 42

/*
 * Cap ndev at 64 so we don't spend all our time doing legal-but-slow
 * large allocations.  AFL++ will explore values up to this cap quickly.
 */
#define MAX_NDEV_FUZZ 64

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < 4)
        return 0;

    /*
     * Clamp the ndev field in the copy we feed to the parser so we don't
     * OOM the fuzzer process with a 2^32-device list.
     */
    uint8_t buf[FUZZ_BUF_MAX];
    size_t n = size < FUZZ_BUF_MAX ? size : FUZZ_BUF_MAX;
    memcpy(buf, data, n);

    uint32_t ndev_be;
    memcpy(&ndev_be, buf, 4);
    uint32_t ndev = ntohl(ndev_be);
    if (ndev > MAX_NDEV_FUZZ) {
        ndev = MAX_NDEV_FUZZ;
        uint32_t clamped = htonl(ndev);
        memcpy(buf, &clamped, 4);
    }

    fuzz_reset(buf, n);

    struct usbip_exported_devices edevs;
    memset(&edevs, 0, sizeof(edevs));

    usbip_net_recv_op_devlist_reply(FAKE_FD, &edevs);
    usbip_exported_devices_free(&edevs);

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
