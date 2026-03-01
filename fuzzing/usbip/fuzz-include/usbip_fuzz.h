#pragma once
/*
 * usbip_fuzz.h — fuzz control header, included before any usbip source.
 *
 * Provides:
 *   - global fuzz buffer (populated by harness main, consumed by __wrap_recv)
 *   - logging macro stubs so usbip source compiles without a real logging lib
 *   - usbip_header wire-format structs for fuzz_urb (not in userspace headers)
 *
 * Protocol constants (USBIP_VERSION, OP_*, SYSFS_BUS_ID_SIZE, etc.) are NOT
 * defined here — they come from usbip_common.h / usbip_network.h / config.h.
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
 */
extern unsigned long usbip_debug_flag;

/*
 * ── USB/IP URB PDU wire-format constants and structs ──────────────────
 * struct usbip_header lives only in the kernel's internal headers, not in
 * any userspace UAPI. Define the wire layout here for fuzz_urb.c so it
 * can call usbip_net_recv() and inspect the PDU fields.
 *
 * Matches drivers/usb/usbip/usbip_common.h — do not change field order.
 */
#define USBIP_CMD_SUBMIT    0x00000001
#define USBIP_CMD_UNLINK    0x00000002
#define USBIP_RET_SUBMIT    0x00000003
#define USBIP_RET_UNLINK    0x00000004

/* PDU header is 48 bytes on the wire (20-byte basic + 28-byte union) */
#define USBIP_PDU_HDR_SIZE  48

struct usbip_header_basic {
    uint32_t command;
    uint32_t seqnum;
    uint32_t devid;
    uint32_t direction;
    uint32_t ep;
};

struct usbip_header_cmd_submit {
    uint32_t transfer_flags;
    int32_t  transfer_buffer_length;
    int32_t  start_frame;
    int32_t  number_of_packets;
    int32_t  interval;
    uint8_t  setup[8];
};

struct usbip_header_ret_submit {
    int32_t  status;
    int32_t  actual_length;
    int32_t  start_frame;
    int32_t  number_of_packets;
    int32_t  error_count;
};

struct usbip_header_cmd_unlink { uint32_t seqnum; };
struct usbip_header_ret_unlink { int32_t  status; };

struct usbip_header {
    struct usbip_header_basic base;
    union {
        struct usbip_header_cmd_submit  cmd_submit;
        struct usbip_header_ret_submit  ret_submit;
        struct usbip_header_cmd_unlink  cmd_unlink;
        struct usbip_header_ret_unlink  ret_unlink;
    } u;
};
