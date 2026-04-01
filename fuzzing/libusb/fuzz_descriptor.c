/*
 * Harness: config/interface/endpoint descriptor chain via raw_desc_to_config().
 * Targets: parse_configuration -> parse_interface -> parse_endpoint (all static).
 */

#include "fuzz-include/libusb_fuzz.h"
#include "libusb-src/libusb/descriptor.c"

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    struct libusb_config_descriptor *config = NULL;
    int r = raw_desc_to_config(NULL, data,
        (int)(size > (size_t)INT_MAX ? INT_MAX : size), &config);
    if (r == LIBUSB_SUCCESS && config)
        libusb_free_config_descriptor(config);
    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
int main(void)
{
    __AFL_INIT();
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000))
        fuzz_one(buf, __AFL_FUZZ_TESTCASE_LEN);
    return 0;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one(data, size);
}
#endif
