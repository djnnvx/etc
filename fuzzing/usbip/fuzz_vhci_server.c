/*
 * fuzz_vhci_server.c — Two-sided USB-IP fuzzer: malicious server targeting vhci-hcd.
 *
 * WHAT THIS TESTS (vs. fuzz_urb.c)
 * ─────────────────────────────────
 * fuzz_urb.c exercises the *userspace* copy of the URB parsing code (linked from
 * tools/usb/usbip/).  This binary exercises the *kernel* copy — specifically the
 * vhci-hcd driver's receive path (vhci_rx.c → usbip_recv_xbuff / usbip_recv_iso)
 * which runs without any sandbox and directly handles untrusted network data.
 *
 * CVE-2016-3955: a server sends USBIP_RET_SUBMIT with actual_length >
 * transfer_buffer_length → heap overflow in usbip_recv_xbuff().  The server
 * has full control over actual_length.  fuzz_urb.c can't trigger this in kernel
 * memory; this binary can (with KASAN enabled in the QEMU kernel).
 *
 * ISO OVERFLOW BUGS (usbip_recv_iso / usbip_pad_iso)
 * ───────────────────────────────────────────────────
 * The server controls urb->number_of_packets via the RET_SUBMIT response.
 * In usbip_recv_iso():
 *   int np   = urb->number_of_packets;   // ← server sets this
 *   int size = np * sizeof(*iso);        // integer overflow if np >= 0x08000001
 *   buff     = kzalloc(size, GFP_KERNEL); // undersized allocation
 *   usbip_net_recv(sock, buff, size);    // receives only `size` bytes
 *   for (i = 0; i < np; i++)            // loops np times → OOB read from buff
 *
 * ARCHITECTURE
 * ─────────────
 *   Host  : fuzz_vhci_server <testcase> <host> <port>  (AFL++ target)
 *   VM    : vhci-hcd loaded, usbip-attach-watchdog running (see qemu/init-vhci)
 *
 *   1. Host server listens on <host>:<port>.
 *   2. VM's vhci-hcd client connects (driven by usbip-attach-watchdog in /init-vhci).
 *   3. Server completes USB-IP handshake: read OP_REQ_IMPORT → send OP_REP_IMPORT.
 *   4. USB core enumerates device via EP0 control transfers (GET_DESCRIPTOR etc.).
 *      Server responds with a valid USB Audio Class descriptor chain so that the
 *      snd_usb_audio driver binds and submits ISO URBs.
 *   5. For non-EP0 URBs, server responds with USBIP_RET_SUBMIT packets whose
 *      ret_submit fields (status, actual_length, number_of_packets, etc.) are
 *      overlaid from the AFL++ test case bytes.  ISO descriptor data is appended.
 *   6. If the kernel panics (KASAN report + panic_on_oops=1), the VM reboots,
 *      vhci-hcd drops the connection → ECONNRESET → server exits 1 → AFL++ crash.
 *   7. Watchdog in VM immediately retries `usbip attach` for the next iteration.
 *
 * AFL++ INVOCATION (from run-fuzzers.sh or manually)
 * ────────────────────────────────────────────────────
 *   # in one tmux pane: start QEMU VM in vhci-client mode
 *   qemu-system-x86_64 -kernel bzImage -initrd initramfs-vhci.cpio.gz \
 *     -nographic -append "console=ttyS0 quiet" -m 512M \
 *     -net nic,model=e1000 -net user
 *
 *   # in another pane: run AFL++ against the server
 *   afl-fuzz -S vhci -i corpus/vhci -o output -t 3000 -x dictionaries/usbip.dict \
 *     -- ./fuzz_vhci_server @@ 0.0.0.0 13241
 *
 * COMPILE
 * ────────
 *   afl-clang-fast -O2 -o fuzz_vhci_server fuzz_vhci_server.c
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ── USB/IP protocol constants ─────────────────────────────────────────────── */
#define USBIP_VERSION       0x0111

#define OP_REQ_IMPORT       0x8003
#define OP_REP_IMPORT       0x0003

#define USBIP_CMD_SUBMIT    0x00000001
#define USBIP_CMD_UNLINK    0x00000002
#define USBIP_RET_SUBMIT    0x00000003
#define USBIP_RET_UNLINK    0x00000004

#define SYSFS_BUS_ID_SIZE   32
#define SYSFS_PATH_MAX      256

/* Maximum actual_length / ISO descriptor data we'll allocate+send (to avoid OOM) */
#define MAX_ACTUAL_LEN      (1 << 16)   /* 64 KB */
#define MAX_ISO_DESC_LEN    (1 << 16)   /* 64 KB — kernel won't get more */

/* sizeof(struct usbip_iso_packet_descriptor) in the kernel */
#define ISO_DESC_SIZE       16

/*
 * ISO endpoint number on our virtual audio device.
 * EP1 IN is declared as isochronous in the config descriptor below.
 */
#define ISO_EP_NUM          1

/* ── wire-format structures (all fields in big-endian / network order) ──────── */

struct op_common {
    uint16_t version;
    uint16_t code;
    uint32_t status;
} __attribute__((packed));

struct op_req_import {
    struct op_common hdr;
    char             busid[SYSFS_BUS_ID_SIZE];
} __attribute__((packed));

struct usbip_usb_device {
    char     path[SYSFS_PATH_MAX];
    char     busid[SYSFS_BUS_ID_SIZE];
    uint32_t busnum;
    uint32_t devnum;
    uint32_t speed;
    uint16_t idVendor;
    uint16_t idProduct;
    uint16_t bcdDevice;
    uint8_t  bDeviceClass;
    uint8_t  bDeviceSubClass;
    uint8_t  bDeviceProtocol;
    uint8_t  bConfigurationValue;
    uint8_t  bNumConfigurations;
    uint8_t  bNumInterfaces;
} __attribute__((packed));

struct op_rep_import {
    struct op_common       hdr;
    struct usbip_usb_device dev;
} __attribute__((packed));

struct usbip_header_basic {
    uint32_t command;
    uint32_t seqnum;
    uint32_t devid;
    uint32_t direction;
    uint32_t ep;
} __attribute__((packed));

struct usbip_header_cmd_submit {
    uint32_t transfer_flags;
    int32_t  transfer_buffer_length;
    int32_t  start_frame;
    int32_t  number_of_packets;
    int32_t  interval;
    uint8_t  setup[8];
} __attribute__((packed));

struct usbip_header_ret_submit {
    int32_t status;
    int32_t actual_length;
    int32_t start_frame;
    int32_t number_of_packets;
    int32_t error_count;
    uint8_t pad[8];
} __attribute__((packed));

struct usbip_header {
    struct usbip_header_basic base;
    union {
        struct usbip_header_cmd_submit  cmd_submit;
        struct usbip_header_ret_submit  ret_submit;
        uint8_t                         raw[28];
    } u;
} __attribute__((packed));

/* ── USB Descriptors for virtual USB Audio Class device ────────────────────────
 *
 * We present a minimal USB Audio 1.0 device with:
 *   Interface 0: AudioControl
 *   Interface 1 alt-0: AudioStreaming (zero bandwidth, 0 endpoints)
 *   Interface 1 alt-1: AudioStreaming (active, 1 ISO IN endpoint → EP1)
 *
 * The snd_usb_audio driver (built into typical kernels) will bind to this device
 * and start submitting isochronous URBs on EP1 for audio streaming.
 * Those ISO URBs come back to us as CMD_SUBMIT on ep==1, and we respond with
 * fuzz-controlled RET_SUBMIT.number_of_packets to trigger usbip_recv_iso() bugs.
 *
 * Descriptor chain layout (wTotalLength = 79):
 *   Config(9) + Iface0-AC(9) + AC-Header(9) +
 *   Iface1-alt0(9) + Iface1-alt1(9) + AS-General(7) + FormatType(11) +
 *   EP-ISO-IN(9) + CS-EP(7) = 79
 */

/* Device Descriptor (18 bytes, USB 2.0, per-interface class) */
static const uint8_t usb_device_desc[] = {
    18,         /* bLength */
    0x01,       /* bDescriptorType: DEVICE */
    0x00, 0x02, /* bcdUSB: 2.0 (little-endian) */
    0x00,       /* bDeviceClass: defined per-interface */
    0x00,       /* bDeviceSubClass */
    0x00,       /* bDeviceProtocol */
    64,         /* bMaxPacketSize0: 64 bytes for HS control */
    0x34, 0x12, /* idVendor: 0x1234 */
    0x78, 0x56, /* idProduct: 0x5678 */
    0x00, 0x01, /* bcdDevice: 1.0 */
    0,          /* iManufacturer */
    0,          /* iProduct */
    0,          /* iSerialNumber */
    1,          /* bNumConfigurations */
};

/*
 * Full Configuration Descriptor chain.
 * wTotalLength = 79 (see layout above).
 * bNumInterfaces = 2  (AudioControl + AudioStreaming).
 */
static const uint8_t usb_config_desc[] = {
    /* ── Configuration Descriptor (9 bytes) ── */
    9, 0x02,        /* bLength, bDescriptorType: CONFIGURATION */
    79, 0,          /* wTotalLength: 79 (LE) */
    2,              /* bNumInterfaces */
    1,              /* bConfigurationValue */
    0,              /* iConfiguration */
    0x80,           /* bmAttributes: bus-powered, no remote wakeup */
    50,             /* bMaxPower: 100 mA */

    /* ── Interface 0: AudioControl, alt 0, 0 endpoints (9 bytes) ── */
    9, 0x04,        /* bLength, bDescriptorType: INTERFACE */
    0,              /* bInterfaceNumber: 0 */
    0,              /* bAlternateSetting: 0 */
    0,              /* bNumEndpoints: 0 (control-only AC interface) */
    0x01,           /* bInterfaceClass: Audio */
    0x01,           /* bInterfaceSubClass: AudioControl */
    0x00,           /* bInterfaceProtocol */
    0,              /* iInterface */

    /* ── AudioControl Class-Specific Interface: HEADER (9 bytes) ── */
    9, 0x24,        /* bLength, bDescriptorType: CS_INTERFACE */
    0x01,           /* bDescriptorSubType: HEADER */
    0x00, 0x01,     /* bcdADC: 1.0 (LE) */
    9, 0,           /* wTotalLength: 9 bytes AC-only (LE) */
    1,              /* bInCollection: 1 streaming interface */
    1,              /* baInterfaceNr[0]: interface 1 is the streaming interface */

    /* ── Interface 1: AudioStreaming, alt 0 — zero bandwidth (9 bytes) ── */
    9, 0x04,        /* bLength, bDescriptorType: INTERFACE */
    1,              /* bInterfaceNumber: 1 */
    0,              /* bAlternateSetting: 0 */
    0,              /* bNumEndpoints: 0 (idle setting) */
    0x01,           /* bInterfaceClass: Audio */
    0x02,           /* bInterfaceSubClass: AudioStreaming */
    0x00,           /* bInterfaceProtocol */
    0,              /* iInterface */

    /* ── Interface 1: AudioStreaming, alt 1 — active ISO streaming (9 bytes) ── */
    9, 0x04,        /* bLength, bDescriptorType: INTERFACE */
    1,              /* bInterfaceNumber: 1 */
    1,              /* bAlternateSetting: 1 */
    1,              /* bNumEndpoints: 1 (the ISO IN endpoint) */
    0x01,           /* bInterfaceClass: Audio */
    0x02,           /* bInterfaceSubClass: AudioStreaming */
    0x00,           /* bInterfaceProtocol */
    0,              /* iInterface */

    /* ── AudioStreaming Class-Specific Interface: AS_GENERAL (7 bytes) ── */
    7, 0x24,        /* bLength, bDescriptorType: CS_INTERFACE */
    0x01,           /* bDescriptorSubType: AS_GENERAL */
    1,              /* bTerminalLink: Terminal ID 1 (placeholder) */
    1,              /* bDelay: 1 frame pipeline delay */
    0x01, 0x00,     /* wFormatTag: PCM (LE) */

    /* ── AudioStreaming Class-Specific Interface: FORMAT_TYPE_I (11 bytes) ── */
    11, 0x24,       /* bLength, bDescriptorType: CS_INTERFACE */
    0x02,           /* bDescriptorSubType: FORMAT_TYPE */
    0x01,           /* bFormatType: FORMAT_TYPE_I */
    2,              /* bNrChannels: stereo */
    2,              /* bSubframeSize: 2 bytes per sample */
    16,             /* bBitResolution: 16 bits */
    1,              /* bSamFreqType: 1 discrete frequency */
    0x44, 0xAC, 0x00, /* tSamFreq[0]: 44100 Hz (3-byte LE: 0x00AC44) */

    /* ── Isochronous IN Endpoint (EP1 IN): bmAttributes=iso/async/data (9 bytes) ── */
    9, 0x05,        /* bLength, bDescriptorType: ENDPOINT */
    0x81,           /* bEndpointAddress: EP1 IN (0x80 | 1) */
    0x01,           /* bmAttributes: isochronous, no sync, data */
    196, 0,         /* wMaxPacketSize: 196 bytes (stereo 16-bit 44100Hz @ 1kHz frames, LE) */
    1,              /* bInterval: every 1 ms (full-speed) or 1 microframe (high-speed) */
    0,              /* bRefresh */
    0,              /* bSynchAddress */

    /* ── AudioStreaming Class-Specific Endpoint: EP_GENERAL (7 bytes) ── */
    7, 0x25,        /* bLength, bDescriptorType: CS_ENDPOINT */
    0x01,           /* bDescriptorSubType: EP_GENERAL */
    0x01,           /* bmAttributes: sampling frequency control */
    0,              /* bLockDelayUnits */
    0x00, 0x00,     /* wLockDelay: 0 */
};

/* Device Qualifier Descriptor (10 bytes) — required for USB 2.0 high-speed devices */
static const uint8_t usb_devqual_desc[] = {
    10,         /* bLength */
    0x06,       /* bDescriptorType: DEVICE_QUALIFIER */
    0x00, 0x02, /* bcdUSB: 2.0 */
    0x00,       /* bDeviceClass */
    0x00,       /* bDeviceSubClass */
    0x00,       /* bDeviceProtocol */
    64,         /* bMaxPacketSize0 */
    1,          /* bNumConfigurations */
    0,          /* bReserved */
};

/* ── helpers ────────────────────────────────────────────────────────────────── */

static int recv_all(int fd, void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t r = recv(fd, (char *)buf + done, len - done, 0);
        if (r <= 0)
            return -1;
        done += (size_t)r;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t r = send(fd, (const char *)buf + done, len - done, MSG_NOSIGNAL);
        if (r <= 0)
            return -1;
        done += (size_t)r;
    }
    return 0;
}

/* ── handshake: read OP_REQ_IMPORT, send OP_REP_IMPORT ─────────────────────── */

static int do_handshake(int sock)
{
    struct op_req_import req;
    memset(&req, 0, sizeof(req));
    if (recv_all(sock, &req, sizeof(req)) < 0)
        return -1;

    uint16_t code = ntohs(req.hdr.code);
    if (code != OP_REQ_IMPORT)
        return -1;

    /*
     * Report our virtual device as USB_SPEED_HIGH audio class device.
     * bDeviceClass=0 (per-interface) with bNumInterfaces=2 matches the
     * config descriptor we return for GET_DESCRIPTOR.
     */
    struct op_rep_import rep;
    memset(&rep, 0, sizeof(rep));
    rep.hdr.version = htons(USBIP_VERSION);
    rep.hdr.code    = htons(OP_REP_IMPORT);
    rep.hdr.status  = htonl(0);

    strncpy(rep.dev.path,  "/sys/devices/pci0000:00/0000:00:01.0/usb1/1-1", SYSFS_PATH_MAX - 1);
    strncpy(rep.dev.busid, "1-1", SYSFS_BUS_ID_SIZE - 1);
    rep.dev.busnum  = htonl(1);
    rep.dev.devnum  = htonl(1);
    rep.dev.speed   = htonl(3);       /* USB_SPEED_HIGH */
    rep.dev.idVendor  = htons(0x1234);
    rep.dev.idProduct = htons(0x5678);
    rep.dev.bcdDevice = htons(0x0100);
    rep.dev.bDeviceClass       = 0;   /* per-interface */
    rep.dev.bDeviceSubClass    = 0;
    rep.dev.bDeviceProtocol    = 0;
    rep.dev.bConfigurationValue = 1;
    rep.dev.bNumConfigurations  = 1;
    rep.dev.bNumInterfaces      = 2;  /* AudioControl + AudioStreaming */

    return send_all(sock, &rep, sizeof(rep));
}

/* ── EP0 control transfer handler ───────────────────────────────────────────── *
 *
 * Responds to USB control requests from the kernel USB core during enumeration.
 * Without valid responses here, USB enumeration fails and no driver ever binds,
 * so no bulk/ISO URBs are submitted and the interesting kernel paths are never hit.
 *
 * Setup packet fields:
 *   setup[0]: bmRequestType
 *   setup[1]: bRequest
 *   setup[2..3]: wValue  (descriptor type in high byte for GET_DESCRIPTOR)
 *   setup[4..5]: wIndex
 *   setup[6..7]: wLength (max bytes host wants back)
 */

/* Send a RET_SUBMIT for a control transfer with an optional data payload */
static int send_ctrl_response(int sock, struct usbip_header *hdr,
                              int32_t status,
                              const void *data, uint32_t data_len)
{
    struct usbip_header resp;
    memset(&resp, 0, sizeof(resp));
    resp.base.command   = htonl(USBIP_RET_SUBMIT);
    resp.base.seqnum    = hdr->base.seqnum;
    resp.base.devid     = hdr->base.devid;
    resp.base.direction = hdr->base.direction;
    resp.base.ep        = hdr->base.ep;
    resp.u.ret_submit.status         = htonl((uint32_t)status);
    resp.u.ret_submit.actual_length  = htonl(data_len);
    resp.u.ret_submit.start_frame    = 0;
    resp.u.ret_submit.number_of_packets = 0;
    resp.u.ret_submit.error_count    = 0;

    if (send_all(sock, &resp, sizeof(resp)) < 0)
        return -1;
    if (data && data_len > 0) {
        if (send_all(sock, data, data_len) < 0)
            return -1;
    }
    return 0;
}

static int handle_ep0(int sock, struct usbip_header *hdr)
{
    uint8_t *setup  = hdr->u.cmd_submit.setup;
    uint8_t  breq   = setup[1];                        /* bRequest */
    uint8_t  dtype  = setup[3];                        /* descriptor type (high byte of wValue) */
    uint16_t wlen   = (uint16_t)setup[6] | ((uint16_t)setup[7] << 8);

    /* Drain any OUT data payload the host sent (unlikely for enumeration) */
    int32_t tbl = ntohl(hdr->u.cmd_submit.transfer_buffer_length);
    if (ntohl(hdr->base.direction) == 0 /* USBIP_DIR_OUT */ && tbl > 0) {
        uint8_t drain[MAX_ACTUAL_LEN];
        int dlen = tbl < MAX_ACTUAL_LEN ? tbl : MAX_ACTUAL_LEN;
        recv_all(sock, drain, (size_t)dlen);
    }

    if (breq == 0x06) {
        /* GET_DESCRIPTOR */
        const uint8_t *desc     = NULL;
        uint32_t       desc_len = 0;

        switch (dtype) {
        case 0x01: /* DEVICE */
            desc     = usb_device_desc;
            desc_len = sizeof(usb_device_desc);
            break;
        case 0x02: /* CONFIGURATION */
            desc     = usb_config_desc;
            desc_len = sizeof(usb_config_desc);
            break;
        case 0x06: /* DEVICE QUALIFIER */
            desc     = usb_devqual_desc;
            desc_len = sizeof(usb_devqual_desc);
            break;
        default:
            /* String, HID, etc. — STALL (no descriptor) */
            return send_ctrl_response(sock, hdr, -32 /* -EPIPE */, NULL, 0);
        }

        /* Honour the host's wLength limit */
        if (desc_len > wlen)
            desc_len = wlen;

        return send_ctrl_response(sock, hdr, 0, desc, desc_len);

    } else if (breq == 0x09 || /* SET_CONFIGURATION */
               breq == 0x0B || /* SET_INTERFACE */
               breq == 0x01 || /* CLEAR_FEATURE */
               breq == 0x03 || /* SET_FEATURE */
               breq == 0x0A    /* GET_INTERFACE */) {
        /* Acknowledge with empty success */
        return send_ctrl_response(sock, hdr, 0, NULL, 0);

    } else {
        /* Unknown/unsupported request — STALL */
        return send_ctrl_response(sock, hdr, -32 /* -EPIPE */, NULL, 0);
    }
}

/* ── main fuzzing loop ──────────────────────────────────────────────────────── *
 *
 * Dispatch:
 *   EP0  → handle_ep0() with valid descriptor responses (enables enumeration)
 *   EP1  → fuzz RET_SUBMIT; ISO descriptor data is also sent (enables iso path)
 *   EPx  → fuzz RET_SUBMIT (bulk/interrupt — triggers xbuff path)
 */

static int fuzz_loop(int sock, const uint8_t *fuzz, size_t fuzz_len)
{
    size_t fuzz_off = 0;

    static uint8_t payload[MAX_ACTUAL_LEN];
    memset(payload, 0xcc, sizeof(payload));

    static uint8_t iso_buf[MAX_ISO_DESC_LEN];
    memset(iso_buf, 0x00, sizeof(iso_buf));

    for (;;) {
        struct usbip_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        if (recv_all(sock, &hdr, sizeof(hdr)) < 0)
            return 0;

        uint32_t cmd = ntohl(hdr.base.command);
        uint32_t ep  = ntohl(hdr.base.ep);

        if (cmd == USBIP_CMD_SUBMIT) {

            /* ── EP0: control transfer — respond with valid USB descriptors ── */
            if (ep == 0) {
                if (handle_ep0(sock, &hdr) < 0)
                    return 1;
                continue;
            }

            /* ── Non-EP0: drain OUT payload ── */
            int32_t tbl = ntohl(hdr.u.cmd_submit.transfer_buffer_length);
            if (ntohl(hdr.base.direction) == 0 /* USBIP_DIR_OUT */ && tbl > 0) {
                int drain_len = tbl < MAX_ACTUAL_LEN ? tbl : MAX_ACTUAL_LEN;
                uint8_t drain[MAX_ACTUAL_LEN];
                recv_all(sock, drain, (size_t)drain_len);
            }

            /* ── Build RET_SUBMIT with fuzz bytes overlaid on the union ── */
            struct usbip_header resp;
            memset(&resp, 0, sizeof(resp));
            resp.base.command   = htonl(USBIP_RET_SUBMIT);
            resp.base.seqnum    = hdr.base.seqnum;
            resp.base.devid     = hdr.base.devid;
            resp.base.direction = hdr.base.direction;
            resp.base.ep        = hdr.base.ep;

            /* Overlay fuzz bytes onto the 28-byte ret_submit union */
            size_t overlay = fuzz_len - fuzz_off;
            if (overlay > sizeof(resp.u.raw))
                overlay = sizeof(resp.u.raw);
            memcpy(resp.u.raw, fuzz + fuzz_off, overlay);
            fuzz_off += overlay;

            /* Clamp actual_length for the host-side payload send */
            int32_t actual_len = ntohl(resp.u.ret_submit.actual_length);
            int32_t send_len   = actual_len;
            if (send_len < 0)       send_len = 0;
            if (send_len > MAX_ACTUAL_LEN) send_len = MAX_ACTUAL_LEN;

            if (send_all(sock, &resp, sizeof(resp)) < 0)
                return 1;

            /* Send xbuff (actual_length bytes) */
            if (send_len > 0) {
                if (send_all(sock, payload, (size_t)send_len) < 0)
                    return 1;
            }

            /*
             * ── ISO descriptor data (EP1 only) ──────────────────────────────
             *
             * For ISO URBs the kernel expects, AFTER the xbuff:
             *   number_of_packets × sizeof(struct usbip_iso_packet_descriptor)
             * bytes of ISO frame descriptors.
             *
             * The overflow attack: if number_of_packets is large enough that
             *   np * ISO_DESC_SIZE  overflows int32 (e.g. np=0x08000001 → wraps
             *   to a small value), the kernel allocates a small buffer but loops
             *   np times → KASAN heap OOB.
             *
             * We mirror the kernel's 32-bit truncated multiplication so we send
             * exactly the number of bytes the (buggy) kernel will recv(), keeping
             * the connection alive for the subsequent OOB loop to fire.
             */
            if (ep == ISO_EP_NUM) {
                int32_t np = ntohl(resp.u.ret_submit.number_of_packets);
                if (np > 0) {
                    /*
                     * Replicate the kernel's 32-bit overflow:
                     *   uint32_t size = (uint32_t)np * ISO_DESC_SIZE;
                     * If np * 16 wraps to a small value, we send that many bytes
                     * and the kernel will allocate the same small buffer, then
                     * loop np times reading OOB → KASAN hit.
                     */
                    uint32_t iso_size = (uint32_t)((uint32_t)np * (uint32_t)ISO_DESC_SIZE);
                    uint32_t iso_send = iso_size;
                    if (iso_send > MAX_ISO_DESC_LEN)
                        iso_send = MAX_ISO_DESC_LEN;
                    if (iso_send > 0) {
                        if (send_all(sock, iso_buf, (size_t)iso_send) < 0)
                            return 1;
                    }
                }
            }

            if (fuzz_off >= fuzz_len)
                return 0;

        } else if (cmd == USBIP_CMD_UNLINK) {
            struct usbip_header resp;
            memset(&resp, 0, sizeof(resp));
            resp.base.command = htonl(USBIP_RET_UNLINK);
            resp.base.seqnum  = hdr.base.seqnum;
            resp.base.devid   = hdr.base.devid;
            /* status = -ENOENT (-2), big-endian */
            resp.u.raw[0] = 0xff; resp.u.raw[1] = 0xff;
            resp.u.raw[2] = 0xff; resp.u.raw[3] = 0xfe;
            if (send_all(sock, &resp, sizeof(resp)) < 0)
                return 1;
        } else {
            return 0;
        }
    }
}

/* ── entry point ─────────────────────────────────────────────────────────────── */

static uint8_t fuzz_buf[1 << 16];

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <testcase> <bind-addr> <port>\n"
                        "  testcase  — AFL++ @@ input file\n"
                        "  bind-addr — address to listen on (e.g. 0.0.0.0)\n"
                        "  port      — TCP port (e.g. 13241)\n",
                argv[0]);
        return 1;
    }

    const char *testcase = argv[1];
    const char *bindaddr = argv[2];
    int         port     = atoi(argv[3]);

    int fd = open(testcase, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    ssize_t fuzz_len = read(fd, fuzz_buf, sizeof(fuzz_buf));
    close(fd);
    if (fuzz_len <= 0)
        return 0;

    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(srv, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, bindaddr, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad bind address: %s\n", bindaddr);
        return 1;
    }

    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(srv, 1) < 0) { perror("listen"); return 1; }

    /* Wait up to 3 seconds for the VM to connect */
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int cli = accept(srv, NULL, NULL);
    close(srv);
    if (cli < 0)
        return 0;  /* timeout — not a crash */

    struct timeval iotv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &iotv, sizeof(iotv));
    setsockopt(cli, SOL_SOCKET, SO_SNDTIMEO, &iotv, sizeof(iotv));

    int one = 1;
    setsockopt(cli, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (do_handshake(cli) < 0) {
        close(cli); return 0;
    }

    int rc = fuzz_loop(cli, fuzz_buf, (size_t)fuzz_len);
    close(cli);
    return rc;  /* 1 = ECONNRESET = kernel panic → AFL++ crash */
}
