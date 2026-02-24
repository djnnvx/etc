#pragma once
/*
 * usbip_fuzz.h — fuzz control header, included before any usbip source.
 *
 * Provides:
 *   - global fuzz buffer (populated by harness main, consumed by __wrap_recv)
 *   - logging macro stubs so usbip source compiles without a real logging lib
 *   - protocol constants / struct aliases for use in harnesses
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* ── fuzz buffer (defined in mock_syscalls.c, declared here) ──────── */
#define FUZZ_BUF_MAX (1 << 16)  /* 64 KB */

extern uint8_t  g_fuzz_buf[FUZZ_BUF_MAX];
extern size_t   g_fuzz_len;
extern size_t   g_fuzz_offset;

static inline void fuzz_reset(const uint8_t *data, size_t size) {
    size_t n = size < FUZZ_BUF_MAX ? size : FUZZ_BUF_MAX;
    memcpy(g_fuzz_buf, data, n);
    g_fuzz_len    = n;
    g_fuzz_offset = 0;
}

/* ── silence usbip logging ────────────────────────────────────────── */
#ifndef pr_err
# define pr_err(fmt, ...)   do { } while (0)
#endif
#ifndef pr_warn
# define pr_warn(fmt, ...)  do { } while (0)
#endif
#ifndef pr_info
# define pr_info(fmt, ...)  do { } while (0)
#endif
#ifndef pr_debug
# define pr_debug(fmt, ...) do { } while (0)
#endif

/* usbip uses these debug wrappers over pr_debug */
#ifndef dbg
# define dbg(fmt, ...)               do { } while (0)
#endif
#ifndef usbip_dbg_xmit
# define usbip_dbg_xmit(fmt, ...)    do { } while (0)
#endif
#ifndef usbip_dbg_sysfs
# define usbip_dbg_sysfs(fmt, ...)   do { } while (0)
#endif
#ifndef usbip_dbg_urb
# define usbip_dbg_urb(fmt, ...)     do { } while (0)
#endif

/*
 * usbip_debug_flag — extern referenced by logging macros in usbip_common.h.
 * Set to 0 so all debug paths are no-ops.
 */
extern unsigned long usbip_debug_flag;

/* ── USB/IP protocol constants ────────────────────────────────────── */
#define USBIP_VERSION       0x0111

#define OP_REQUEST          (0x80 << 8)
#define OP_REPLY            (0x00 << 8)

#define OP_DEVLIST          0x0005
#define OP_IMPORT           0x0003

#define OP_REQ_DEVLIST      (OP_REQUEST | OP_DEVLIST)   /* 0x8005 */
#define OP_REP_DEVLIST      (OP_REPLY   | OP_DEVLIST)   /* 0x0005 */
#define OP_REQ_IMPORT       (OP_REQUEST | OP_IMPORT)    /* 0x8003 */
#define OP_REP_IMPORT       (OP_REPLY   | OP_IMPORT)    /* 0x0003 */

#define USBIP_CMD_SUBMIT    0x00000001
#define USBIP_CMD_UNLINK    0x00000002
#define USBIP_RET_SUBMIT    0x00000003
#define USBIP_RET_UNLINK    0x00000004

#define SYSFS_BUS_ID_SIZE   32

/* op_common is 8 bytes on the wire */
#define OP_COMMON_SIZE      8
