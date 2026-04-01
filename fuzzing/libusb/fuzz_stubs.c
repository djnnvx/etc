/*
 * Definitions for extern symbols declared in libusbi.h but normally defined
 * in core.c / sync.c, which we don't compile in fuzz builds.
 */

#include "fuzz-include/libusb_fuzz.h"
#include "libusb-src/libusb/libusbi.h"

uint8_t g_fuzz_buf[FUZZ_BUF_MAX];
size_t  g_fuzz_len;
size_t  g_fuzz_offset;

/* Zero-init backend; all function pointers are NULL — never called by parsers */
const struct usbi_os_backend usbi_backend;

struct libusb_context *usbi_default_context  = NULL;
struct libusb_context *usbi_fallback_context = NULL;

usbi_mutex_static_t active_contexts_lock = USBI_MUTEX_INITIALIZER;
struct list_head    active_contexts_list;

usbi_mutex_static_t linux_hotplug_lock = USBI_MUTEX_INITIALIZER;

/* Transfer stubs — referenced by public API functions compiled in via
 * descriptor.c but never called from our harness entry points. */
int API_EXPORTED libusb_control_transfer(libusb_device_handle *dev_handle,
    uint8_t request_type, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
    unsigned char *data, uint16_t wLength, unsigned int timeout)
{
    (void)dev_handle; (void)request_type; (void)bRequest;
    (void)wValue; (void)wIndex; (void)data; (void)wLength; (void)timeout;
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

int API_EXPORTED libusb_bulk_transfer(libusb_device_handle *dev_handle,
    unsigned char endpoint, unsigned char *data, int length,
    int *actual_length, unsigned int timeout)
{
    (void)dev_handle; (void)endpoint; (void)data;
    (void)length; (void)actual_length; (void)timeout;
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

int API_EXPORTED libusb_interrupt_transfer(libusb_device_handle *dev_handle,
    unsigned char endpoint, unsigned char *data, int length,
    int *actual_length, unsigned int timeout)
{
    (void)dev_handle; (void)endpoint; (void)data;
    (void)length; (void)actual_length; (void)timeout;
    return LIBUSB_ERROR_NOT_SUPPORTED;
}
