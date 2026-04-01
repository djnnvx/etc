/*
 * Extraction of parse_config_descriptors() + seek_to_next_config() from
 * linux_usbfs.c. Verbatim logic, local type definitions, fuzz-visible entry point.
 */

#include "fuzz-include/libusb_fuzz.h"
#include "libusb-src/libusb/libusbi.h"

struct config_descriptor {
    struct usbi_configuration_descriptor *desc;
    size_t actual_len;
};

struct linux_device_priv {
    char   *sysfs_dir;
    void   *descriptors;
    size_t  descriptors_len;
    struct config_descriptor *config_descriptors;
    int     active_config;
};

static int seek_to_next_config(struct libusb_context *ctx,
    uint8_t *buffer, size_t len)
{
    struct usbi_descriptor_header *header;
    int offset = LIBUSB_DT_CONFIG_SIZE;

    buffer += LIBUSB_DT_CONFIG_SIZE;
    len    -= LIBUSB_DT_CONFIG_SIZE;

    while (len > 0) {
        if (len < 2) {
            usbi_err(ctx, "remaining descriptor length too small %zu/2", len);
            return LIBUSB_ERROR_IO;
        }
        header = (struct usbi_descriptor_header *)buffer;
        if (header->bDescriptorType == LIBUSB_DT_CONFIG)
            return offset;
        if (header->bLength < 2) {
            usbi_err(ctx, "invalid descriptor bLength %hhu", header->bLength);
            return LIBUSB_ERROR_IO;
        }
        if (len < header->bLength) {
            usbi_err(ctx, "bLength overflow by %zu bytes",
                (size_t)header->bLength - len);
            return LIBUSB_ERROR_IO;
        }
        offset += header->bLength;
        buffer += header->bLength;
        len    -= header->bLength;
    }

    usbi_err(ctx, "config descriptor not found");
    return LIBUSB_ERROR_IO;
}

int fuzz_parse_config_descriptors(struct libusb_device *dev)
{
    struct libusb_context *ctx = DEVICE_CTX(dev);
    struct linux_device_priv *priv = usbi_get_device_priv(dev);
    struct usbi_device_descriptor *device_desc;
    uint8_t idx, num_configs;
    uint8_t *buffer;
    size_t remaining;

    device_desc = priv->descriptors;
    num_configs = device_desc->bNumConfigurations;
    if (num_configs == 0)
        return 0;

    priv->config_descriptors = malloc(
        num_configs * sizeof(priv->config_descriptors[0]));
    if (!priv->config_descriptors)
        return LIBUSB_ERROR_NO_MEM;

    buffer    = (uint8_t *)priv->descriptors + LIBUSB_DT_DEVICE_SIZE;
    remaining = priv->descriptors_len - LIBUSB_DT_DEVICE_SIZE;

    for (idx = 0; idx < num_configs; idx++) {
        struct usbi_configuration_descriptor *config_desc;
        uint16_t config_len;

        if (remaining < LIBUSB_DT_CONFIG_SIZE) {
            usbi_err(ctx, "short descriptor read %zu/%d",
                remaining, LIBUSB_DT_CONFIG_SIZE);
            return LIBUSB_ERROR_IO;
        }

        config_desc = (struct usbi_configuration_descriptor *)buffer;
        if (config_desc->bDescriptorType != LIBUSB_DT_CONFIG) {
            usbi_err(ctx, "not a config descriptor (type 0x%02x)",
                config_desc->bDescriptorType);
            return LIBUSB_ERROR_IO;
        } else if (config_desc->bLength < LIBUSB_DT_CONFIG_SIZE) {
            usbi_err(ctx, "invalid descriptor bLength %u", config_desc->bLength);
            return LIBUSB_ERROR_IO;
        }

        config_len = libusb_le16_to_cpu(config_desc->wTotalLength);
        if (config_len < LIBUSB_DT_CONFIG_SIZE) {
            usbi_err(ctx, "invalid wTotalLength %u", config_len);
            return LIBUSB_ERROR_IO;
        }

        /* sysfs_dir == NULL → usbfs path: wTotalLength used directly */
        if (!priv->sysfs_dir) {
            if (config_len > remaining) {
                usbi_warn(ctx, "short descriptor read %zu/%u", remaining, config_len);
                config_len = (uint16_t)remaining;
            }
        }

        priv->config_descriptors[idx].desc       = config_desc;
        priv->config_descriptors[idx].actual_len = config_len;
        buffer    += config_len;
        remaining -= config_len;
    }

    return LIBUSB_SUCCESS;
}
