/*
 * Harness: IAD two-pass parsing via raw_desc_to_iad_array().
 */

#include "fuzz-include/libusb_fuzz.h"
#include "libusb-src/libusb/descriptor.c"

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    struct libusb_interface_association_descriptor_array *iad_array = NULL;
    int r = raw_desc_to_iad_array(NULL, data,
        (int)(size > (size_t)INT_MAX ? INT_MAX : size), &iad_array);
    if (r == LIBUSB_SUCCESS && iad_array)
        libusb_free_interface_association_descriptors(iad_array);
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
