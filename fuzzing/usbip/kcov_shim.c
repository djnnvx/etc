/*
 * kcov_shim.c — KCOV-backed AFL++ coverage shim for QEMU-mode kernel fuzzing.
 *
 * WHAT THIS DOES
 * ───────────────
 * This binary runs INSIDE the QEMU VM.  AFL++ runs on the HOST.  The two
 * communicate over a virtio-serial channel (or a pipe if using netns mode).
 *
 * Per iteration:
 *   1. AFL++ writes the test case bytes over the serial link.
 *   2. This shim reads them, enables KCOV, sends the bytes to usbipd via TCP.
 *   3. usbipd processes them → kernel code executes → KCOV records PC trace.
 *   4. This shim reads the KCOV buffer, hashes consecutive (PC[i], PC[i+1])
 *      pairs as coverage "edges", and writes the edge bitmap back to AFL++ over
 *      the serial link.
 *   5. AFL++ uses the edge bitmap to guide mutation (same as in-process mode
 *      but the coverage comes from the kernel, not userspace).
 *
 * CHANNEL PROTOCOL (over virtio-serial)
 * ───────────────────────────────────────
 *   HOST→GUEST: [len:4 LE][payload:len]   (test case)
 *   GUEST→HOST: [bitmap:MAP_SIZE]          (AFL++ shared map, 64 KB)
 *   GUEST→HOST: [crash:1]                 (0x00 = ok, 0x01 = crash detected)
 *
 * MAP_SIZE = 65536 (matches AFL++ default __AFL_SHM_FUZZ_LEN)
 *
 * QEMU INVOCATION (add to qemu-system-x86_64 command line)
 * ─────────────────────────────────────────────────────────
 *   -chardev socket,id=kcov,path=/tmp/kcov.sock,server=on,wait=off \
 *   -device virtio-serial \
 *   -device virtserialport,chardev=kcov,name=kcov0
 *
 *   # Inside VM /init: exec kcov_shim /dev/vport0p1 127.0.0.1 3240
 *
 * HOST SIDE
 * ─────────
 *   afl-fuzz ... -- ./kcov_host_relay /tmp/kcov.sock @@
 *   (kcov_host_relay is a thin wrapper that reads @@ and writes to the socket)
 *
 * COMPILE (inside VM, or cross-compile)
 * ───────────────────────────────────────
 *   gcc -O2 -static -o kcov_shim kcov_shim.c
 *
 * KERNEL CONFIG REQUIREMENTS
 * ───────────────────────────
 *   CONFIG_KCOV=y
 *   CONFIG_KCOV_ENABLE_COMPARISONS=y
 *   CONFIG_DEBUG_FS=y         (debugfs must be mounted at /sys/kernel/debug)
 *
 * NOTE: KCOV covers code running in task context for the current process.
 * The TCP receive path and usbip parsing run in task context (kthread or
 * workqueue bound to the usbipd process's fd) and WILL be covered.
 * IRQ and softirq handlers will NOT be covered (KCOV limitation).
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ── KCOV kernel ABI ────────────────────────────────────────────────────────── */
/* From linux/kcov.h (reproduced here to avoid kernel header dependency) */
#define KCOV_INIT_TRACE         _IOR('c', 1, unsigned long)
#define KCOV_ENABLE             _IO('c',  100)
#define KCOV_DISABLE            _IO('c',  101)
#define KCOV_TRACE_PC           0

#define KCOV_ENTRIES            (64 * 1024)     /* 64K entries = 512 KB mmap */
#define KCOV_PATH               "/sys/kernel/debug/kcov"

/* ── AFL++ shared map ───────────────────────────────────────────────────────── */
#define MAP_SIZE                (1 << 16)       /* 64 KB — AFL++ default */

/* ── protocol sizes ─────────────────────────────────────────────────────────── */
#define MAX_INPUT               (1 << 16)       /* 64 KB max test case */

/* ── globals ─────────────────────────────────────────────────────────────────── */
static uint8_t  afl_map[MAP_SIZE];              /* coverage edge bitmap */
static uint8_t  ibuf[MAX_INPUT];                /* incoming test case */
static uint64_t *kcov_buf;                      /* mmap of KCOV trace buffer */
static int       kcov_fd = -1;

/* ── KCOV helpers ────────────────────────────────────────────────────────────── */

static int kcov_init(void)
{
    kcov_fd = open(KCOV_PATH, O_RDWR);
    if (kcov_fd < 0) {
        perror("open " KCOV_PATH);
        return -1;
    }

    if (ioctl(kcov_fd, KCOV_INIT_TRACE, KCOV_ENTRIES) < 0) {
        perror("ioctl KCOV_INIT_TRACE");
        return -1;
    }

    kcov_buf = mmap(NULL, KCOV_ENTRIES * sizeof(uint64_t),
                    PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0);
    if (kcov_buf == MAP_FAILED) {
        perror("mmap kcov");
        return -1;
    }

    return 0;
}

static void kcov_reset_and_enable(void)
{
    kcov_buf[0] = 0;        /* reset count */
    ioctl(kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC);
}

static void kcov_disable_and_harvest(void)
{
    ioctl(kcov_fd, KCOV_DISABLE, 0);

    uint64_t count = kcov_buf[0];
    if (count > (uint64_t)(KCOV_ENTRIES - 1))
        count = KCOV_ENTRIES - 1;

    /* Hash consecutive PC pairs as edge coverage.
     * AFL++ treats (src, dst) pairs as edges in the control-flow graph.
     * We use a simple hash: edge = ((pc[i] >> 1) ^ pc[i+1]) % MAP_SIZE
     * This is the same scheme used by honggfuzz and oracle/kernel-fuzzing. */
    for (uint64_t i = 0; i + 1 < count; i++) {
        uint64_t a = kcov_buf[1 + i];
        uint64_t b = kcov_buf[1 + i + 1];
        uint32_t edge = (uint32_t)(((a >> 1) ^ b) % MAP_SIZE);
        if (afl_map[edge] < 255)
            afl_map[edge]++;
    }
}

/* ── TCP helpers ─────────────────────────────────────────────────────────────── */

static int recv_all(int fd, void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t r = recv(fd, (char *)buf + done, len - done, 0);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

static int send_all_fd(int fd, const void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t r = write(fd, (const char *)buf + done, len - done);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

static int tcp_connect(const char *host, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, host, &sa.sin_addr);

    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };  /* 200 ms */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

/* ── main loop ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <serial-dev> <usbipd-host> <usbipd-port>\n"
                "  serial-dev   — virtio-serial device (e.g. /dev/vport0p1)\n"
                "  usbipd-host  — usbipd address (usually 127.0.0.1)\n"
                "  usbipd-port  — usbipd port (usually 3240)\n",
                argv[0]);
        return 1;
    }

    const char *serial_dev = argv[1];
    const char *usbipd_host = argv[2];
    int         usbipd_port = atoi(argv[3]);

    signal(SIGPIPE, SIG_IGN);

    /* Open virtio-serial channel to host */
    int serial = open(serial_dev, O_RDWR);
    if (serial < 0) {
        perror("open serial");
        return 1;
    }

    /* Init KCOV */
    if (kcov_init() < 0)
        return 1;

    fprintf(stderr, "[kcov_shim] ready on %s, targeting %s:%d\n",
            serial_dev, usbipd_host, usbipd_port);

    /* Main loop: one iteration per AFL++ test case */
    for (;;) {
        /* ── receive test case from host (via virtio-serial) ── */
        uint32_t len_le;
        if (recv_all(serial, &len_le, 4) < 0)
            break;
        uint32_t ilen = le32toh(len_le);
        if (ilen == 0 || ilen > MAX_INPUT)
            ilen = 0;

        if (ilen > 0 && recv_all(serial, ibuf, ilen) < 0)
            break;

        /* ── reset edge map for this iteration ── */
        memset(afl_map, 0, MAP_SIZE);

        uint8_t crash = 0;

        if (ilen > 0) {
            /* ── enable KCOV ── */
            kcov_reset_and_enable();

            /* ── send payload to usbipd via TCP ── */
            int sock = tcp_connect(usbipd_host, usbipd_port);
            if (sock >= 0) {
                /* Send; ignore errors — crash detection is via KCOV + exit */
                send(sock, ibuf, ilen, MSG_NOSIGNAL);

                /* Wait briefly for response (or connection close) */
                uint8_t rbuf[256];
                ssize_t r = recv(sock, rbuf, sizeof(rbuf), 0);
                if (r < 0 && (errno == ECONNRESET || errno == EPIPE))
                    crash = 1;
                close(sock);
            }

            /* ── disable KCOV and harvest coverage ── */
            kcov_disable_and_harvest();
        }

        /* ── send bitmap + crash byte back to AFL++ ── */
        if (send_all_fd(serial, afl_map, MAP_SIZE) < 0)
            break;
        if (send_all_fd(serial, &crash, 1) < 0)
            break;
    }

    close(serial);
    return 0;
}
