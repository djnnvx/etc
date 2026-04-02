/*
 * Harness: endpoint extra chain walking via libusb_get_ss_endpoint_companion_descriptor().
 *
 * fuzz_descriptor.c parses configs and immediately frees them — it never calls
 * the public API that walks endpoint->extra. This harness does both: parse the
 * config, then call the SS endpoint companion extractor on every endpoint's
 * extra data. That walking loop is completely unexercised by any other harness.
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
    if (r != LIBUSB_SUCCESS || !config)
        return 0;

    for (uint8_t i = 0; i < config->bNumInterfaces; i++) {
        const struct libusb_interface *iface = &config->interface[i];
        for (int a = 0; a < iface->num_altsetting; a++) {
            const struct libusb_interface_descriptor *alt = &iface->altsetting[a];
            for (uint8_t e = 0; e < alt->bNumEndpoints; e++) {
                const struct libusb_endpoint_descriptor *ep = &alt->endpoint[e];

                struct libusb_ss_endpoint_companion_descriptor *comp = NULL;
                libusb_get_ss_endpoint_companion_descriptor(NULL, ep, &comp);
                if (comp)
                    libusb_free_ss_endpoint_companion_descriptor(comp);
            }
        }
    }

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
