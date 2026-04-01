/*
 * Harness: BOS descriptor parsing + all 5 device-capability extractors.
 * Key bugs: platform bLength underflow (line 1268), SSPlus OOB (line 1115).
 */

#include "fuzz-include/libusb_fuzz.h"
#include "libusb-src/libusb/descriptor.c"

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    struct libusb_bos_descriptor *bos = NULL;
    int r = parse_bos(NULL, &bos,
        data, (int)(size > (size_t)INT_MAX ? INT_MAX : size));
    if (r != LIBUSB_SUCCESS || !bos)
        return 0;

    for (uint8_t i = 0; i < bos->bNumDeviceCaps; i++) {
        struct libusb_bos_dev_capability_descriptor *cap = bos->dev_capability[i];

        struct libusb_usb_2_0_extension_descriptor *usb20 = NULL;
        libusb_get_usb_2_0_extension_descriptor(NULL, cap, &usb20);
        if (usb20) libusb_free_usb_2_0_extension_descriptor(usb20);

        struct libusb_ss_usb_device_capability_descriptor *ss = NULL;
        libusb_get_ss_usb_device_capability_descriptor(NULL, cap, &ss);
        if (ss) libusb_free_ss_usb_device_capability_descriptor(ss);

        struct libusb_ssplus_usb_device_capability_descriptor *ssplus = NULL;
        libusb_get_ssplus_usb_device_capability_descriptor(NULL, cap, &ssplus);
        if (ssplus) libusb_free_ssplus_usb_device_capability_descriptor(ssplus);

        struct libusb_container_id_descriptor *cid = NULL;
        libusb_get_container_id_descriptor(NULL, cap, &cid);
        if (cid) libusb_free_container_id_descriptor(cid);

        struct libusb_platform_descriptor *plat = NULL;
        libusb_get_platform_descriptor(NULL, cap, &plat);
        if (plat) libusb_free_platform_descriptor(plat);
    }

    libusb_free_bos_descriptor(bos);
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
