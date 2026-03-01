/*
 * fuzz_devlist.c — USB/IP device-list reply parsing harness.
 *
 * Exercises the devlist reply path:
 *   [ndev:4 BE] + ndev × (usbip_usb_device + bNumInterfaces × usbip_usb_interface)
 *
 * Bug classes: large ndev overflow, malformed device structs, integer overflow
 * in ndev × sizeof(usbip_usb_device), bNumInterfaces out of bounds.
 */

#include "fuzz-include/usbip_fuzz.h"
#include "usbip-src/libsrc/usbip_common.h"
#include "usbip-src/src/usbip_network.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define FAKE_FD       42
#define MAX_NDEV_FUZZ 64

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < sizeof(struct op_devlist_reply))
        return 0;

    uint8_t buf[FUZZ_BUF_MAX];
    size_t n = size < FUZZ_BUF_MAX ? size : FUZZ_BUF_MAX;
    memcpy(buf, data, n);

    /* Clamp ndev so we don't OOM the fuzzer on a 2^32-device list */
    uint32_t ndev_be;
    memcpy(&ndev_be, buf, 4);
    uint32_t ndev = ntohl(ndev_be);
    if (ndev > MAX_NDEV_FUZZ) {
        ndev = MAX_NDEV_FUZZ;
        uint32_t clamped = htonl(ndev);
        memcpy(buf, &clamped, 4);
    }

    fuzz_reset(buf, n);

    struct op_devlist_reply reply;
    memset(&reply, 0, sizeof(reply));
    if (usbip_net_recv(FAKE_FD, &reply, sizeof(reply)) < 0)
        return 0;
    PACK_OP_DEVLIST_REPLY(0, &reply);

    uint32_t num = reply.ndev;
    if (num > MAX_NDEV_FUZZ) num = MAX_NDEV_FUZZ;

    for (uint32_t i = 0; i < num; i++) {
        struct usbip_usb_device udev;
        memset(&udev, 0, sizeof(udev));
        if (usbip_net_recv(FAKE_FD, &udev, sizeof(udev)) < 0)
            return 0;
        usbip_net_pack_usb_device(0, &udev);

        uint8_t nif = udev.bNumInterfaces;
        for (uint8_t j = 0; j < nif; j++) {
            struct usbip_usb_interface uinf;
            memset(&uinf, 0, sizeof(uinf));
            if (usbip_net_recv(FAKE_FD, &uinf, sizeof(uinf)) < 0)
                return 0;
            usbip_net_pack_usb_interface(0, &uinf);
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
