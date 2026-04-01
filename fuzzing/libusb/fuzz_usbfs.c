/*
 * Harness: linux_usbfs parse_config_descriptors via direct priv injection.
 * Input: raw descriptor blob — 18-byte device desc + config descriptors.
 */

#include "fuzz-include/libusb_fuzz.h"
#include "libusb-src/libusb/libusbi.h"

int fuzz_parse_config_descriptors(struct libusb_device *dev);

/* Must match layout in fuzz_usbfs_shim.c */
struct linux_device_priv {
    char   *sysfs_dir;
    void   *descriptors;
    size_t  descriptors_len;
    void   *config_descriptors;
    int     active_config;
};

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < LIBUSB_DT_DEVICE_SIZE)
        return 0;

    size_t dev_padded = PTR_ALIGN(sizeof(struct libusb_device));
    uint8_t *block = calloc(1, dev_padded + sizeof(struct linux_device_priv));
    if (!block)
        return 0;

    struct libusb_device     *dev  = (struct libusb_device *)block;
    struct linux_device_priv *priv = (struct linux_device_priv *)(block + dev_padded);

    memcpy(&dev->device_descriptor, data, LIBUSB_DT_DEVICE_SIZE);

    priv->descriptors = malloc(size);
    if (!priv->descriptors) { free(block); return 0; }
    memcpy(priv->descriptors, data, size);
    priv->descriptors_len = size;

    fuzz_parse_config_descriptors(dev);

    free(priv->config_descriptors);
    free(priv->descriptors);
    free(block);
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
