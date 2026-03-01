/*
 * fuzz_import.c — USB/IP device import reply parsing harness.
 *
 * Exercises op_import_reply parsing: struct op_import_reply contains a
 * usbip_usb_device (busid, speed, descriptor fields).
 *
 * Also exercises the request-builder path: sends op_import_request with
 * a fuzzer-supplied busid, exercising the busid field copy and send path.
 *
 * Bug classes: busid not NUL-terminated, busid with path-traversal chars,
 * busid with format-string tokens, malformed usbip_usb_device struct fields.
 *
 * Input format:
 *   [32-byte busid, possibly without NUL][op_import_reply bytes...]
 */

#include "fuzz-include/usbip_fuzz.h"
#include "usbip-src/libsrc/usbip_common.h"
#include "usbip-src/src/usbip_network.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FAKE_FD   42
#define MIN_INPUT (SYSFS_BUS_ID_SIZE + sizeof(struct op_import_reply))

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < MIN_INPUT)
        return 0;

    /* Path A: parse import reply (server → client direction) */
    fuzz_reset(data + SYSFS_BUS_ID_SIZE, size - SYSFS_BUS_ID_SIZE);

    struct op_import_reply reply;
    memset(&reply, 0, sizeof(reply));
    if (usbip_net_recv(FAKE_FD, &reply, sizeof(reply)) == 0)
        PACK_OP_IMPORT_REPLY(0, &reply);

    /* Path B: build and send import request with fuzz-supplied busid */
    struct op_import_request request;
    memset(&request, 0, sizeof(request));
    memcpy(request.busid, data, SYSFS_BUS_ID_SIZE);
    /* Intentionally don't force NUL-termination — that's the test */
    PACK_OP_IMPORT_REQUEST(1, &request);

    fuzz_reset(data, size);
    usbip_net_send(FAKE_FD, &request, sizeof(request));

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
