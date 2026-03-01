/*
 * fuzz_protocol.c — USB/IP op_common header parsing harness.
 *
 * Exercises usbip_net_recv_op_common() which reads the 8-byte op_common
 * header and validates protocol version + operation code.
 * On success, reads the reply body depending on the opcode.
 *
 * Input format: [version:2 BE][code:2 BE][status:4 BE][... payload ...]
 */

#include "fuzz-include/usbip_fuzz.h"
#include "usbip-src/libsrc/usbip_common.h"
#include "usbip-src/src/usbip_network.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define FAKE_FD 42

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < sizeof(struct op_common))
        return 0;

    fuzz_reset(data, size);

    /*
     * Pass OP_UNSPEC so recv_op_common accepts any opcode.
     * The function reads sizeof(struct op_common) bytes via our mock recv.
     */
    uint16_t code = OP_UNSPEC;
    int status = 0;

    if (usbip_net_recv_op_common(FAKE_FD, &code, &status) < 0)
        return 0;

    /* Consume the reply body to exercise more of the parsing surface */
    switch (code) {
    case OP_REP_DEVLIST: {
        struct op_devlist_reply dr;
        memset(&dr, 0, sizeof(dr));
        if (usbip_net_recv(FAKE_FD, &dr, sizeof(dr)) == 0)
            PACK_OP_DEVLIST_REPLY(0, &dr);
        break;
    }
    case OP_REP_IMPORT: {
        struct op_import_reply ir;
        memset(&ir, 0, sizeof(ir));
        if (usbip_net_recv(FAKE_FD, &ir, sizeof(ir)) == 0)
            PACK_OP_IMPORT_REPLY(0, &ir);
        break;
    }
    default:
        break;
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
