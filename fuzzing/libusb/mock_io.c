/*
 * Syscall intercepts for the linux_usbfs I/O path.
 * Linked via -Wl,--wrap=open,--wrap=read,--wrap=close,--wrap=ioctl,--wrap=write
 *
 * Compiled into fuzz_usbfs but never called by its direct-injection path.
 * Available for a future harness that exercises initialize_device().
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <errno.h>

#define FUZZ_BUF_MAX (1 << 16)
#define FAKE_FD 42

extern uint8_t g_fuzz_buf[FUZZ_BUF_MAX];
extern size_t  g_fuzz_len;
extern size_t  g_fuzz_offset;

int __wrap_open(const char *path, int flags, ...)
{
    (void)flags;
    if (path && __builtin_strstr(path, "/dev/bus/usb"))
        return FAKE_FD;
    errno = ENOENT;
    return -1;
}

ssize_t __wrap_read(int fd, void *buf, size_t len)
{
    extern ssize_t __real_read(int, void *, size_t);
    if (fd != FAKE_FD)
        return __real_read(fd, buf, len);
    if (g_fuzz_offset >= g_fuzz_len)
        return 0;
    size_t avail = g_fuzz_len - g_fuzz_offset;
    size_t n = len < avail ? len : avail;
    memcpy(buf, g_fuzz_buf + g_fuzz_offset, n);
    g_fuzz_offset += n;
    return (ssize_t)n;
}

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    (void)fd;
    /* GET_CAPABILITIES → return all flags */
    if ((request & 0xFF) == 26) {
        va_list ap; va_start(ap, request);
        uint32_t *c = va_arg(ap, uint32_t *); va_end(ap);
        if (c) *c = 0x1F;
        return 0;
    }
    /* GET_SPEED → SuperSpeed Plus */
    if ((request & 0xFF) == 31) return 6;
    return 0;
}

int __wrap_close(int fd)
{
    extern int __real_close(int);
    return fd == FAKE_FD ? 0 : __real_close(fd);
}

ssize_t __wrap_write(int fd, const void *buf, size_t len)
{
    extern ssize_t __real_write(int, const void *, size_t);
    if (fd == 2 || fd == 198 || fd == 199)
        return __real_write(fd, buf, len);
    (void)buf;
    return (ssize_t)len;
}
