/*
 * mock_syscalls.c — recv/send overrides via --wrap linker flags.
 *
 * afl-clang-fast links this with -Wl,--wrap=recv -Wl,--wrap=send so that
 * all recv() calls inside the compiled usbip objects read from g_fuzz_buf
 * instead of a real socket.  send() is a no-op (output discarded).
 *
 * The fuzz buffer is populated by each harness's main() / LLVMFuzzerTestOneInput
 * via fuzz_reset() from usbip_fuzz.h.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#define FUZZ_BUF_MAX (1 << 16)

uint8_t  g_fuzz_buf[FUZZ_BUF_MAX];
size_t   g_fuzz_len;
size_t   g_fuzz_offset;

/* usbip_debug_flag referenced by logging macros; keep at 0 */
unsigned long usbip_debug_flag = 0;

/*
 * udev_context — global udev handle owned by usbip_host_common.c which we
 * don't compile for the fuzz build. Provide a NULL stub; the network
 * parsing paths we target never call udev_device_new_from_subsystem_sysname.
 */
struct udev;
struct udev *udev_context = NULL;

/*
 * __wrap_recv — intercepts every recv() call from the usbip objects.
 * Serves data from g_fuzz_buf in order; returns 0 (EOF) when exhausted.
 *
 * Partial reads are intentionally allowed so usbip_net_xmit's retry loop
 * sees realistic short-read behaviour and AFL++ can explore both the
 * "got full header" and "short read" code paths.
 */
ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags)
{
    (void)fd;
    (void)flags;

    if (g_fuzz_offset >= g_fuzz_len)
        return 0;  /* EOF — caller sees empty read and returns error */

    size_t avail = g_fuzz_len - g_fuzz_offset;
    size_t n = len < avail ? len : avail;
    memcpy(buf, g_fuzz_buf + g_fuzz_offset, n);
    g_fuzz_offset += n;
    return (ssize_t)n;
}

/*
 * __wrap_send — silently discards all outgoing data.
 * Pretends to have sent everything so callers don't error out.
 */
ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags)
{
    (void)fd;
    (void)buf;
    (void)flags;
    return (ssize_t)len;
}

/* Some usbip code paths use write() for logging; silence those too */
ssize_t __wrap_write(int fd, const void *buf, size_t len)
{
    extern ssize_t __real_write(int, const void *, size_t);
    /*
     * Pass through:
     *   fd 2   — stderr (ASAN/abort messages need to reach the terminal)
     *   fd 198 — AFL++ forkserver control pipe  (FORKSRV_FD)
     *   fd 199 — AFL++ forkserver status pipe   (FORKSRV_FD+1)
     *
     * AFL++ runtime calls write(199, hello, 4) to hand-shake with afl-fuzz.
     * Without this pass-through the hello is silently discarded and AFL++
     * deadlocks waiting for the forkserver to become ready.
     */
    if (fd == 2 || fd == 198 || fd == 199)
        return __real_write(fd, buf, len);
    (void)buf;
    return (ssize_t)len;
}
