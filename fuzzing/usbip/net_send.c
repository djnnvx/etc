/*
 * net_send.c — TCP bridge for QEMU-backed AFL++ fuzzing.
 *
 * Reads the AFL++ test-case file (argv[1]), opens a TCP connection to
 * host:port (argv[2]:argv[3]), sends the raw bytes to usbipd running inside
 * the QEMU VM, then exits.
 *
 * Exit codes:
 *   0  — sent OK (or server closed connection normally)
 *   1  — ECONNRESET / SIGPIPE (daemon crashed → AFL++ marks as crash)
 *
 * Retries the connection 3× with 100 ms backoff to handle the brief window
 * when usbipd is being restarted by the watchdog in /init.
 *
 * Usage:
 *   afl-fuzz -S worker -i corpus -o output -t 2000 -- \
 *     ./net_send @@ 127.0.0.1 13240
 *
 * Compile:
 *   gcc -O2 -o net_send net_send.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define MAX_INPUT   (1 << 16)  /* 64 KB — matches FUZZ_BUF_MAX */
#define MAX_RETRIES 3
#define RETRY_MS    100

static void sleep_ms(int ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static uint8_t ibuf[MAX_INPUT];

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <input_file> <host> <port>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    const char *host = argv[2];
    int         port = atoi(argv[3]);

    /* ── read input file ──────────────────────────────────────────── */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    ssize_t len = read(fd, ibuf, sizeof(ibuf));
    close(fd);
    if (len <= 0)
        return 0;   /* empty input — nothing to send */

    /* ── ignore SIGPIPE (treat as connection error, not fatal signal) */
    signal(SIGPIPE, SIG_IGN);

    /* ── connect with retries ─────────────────────────────────────── */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad host: %s\n", host);
        return 1;
    }

    int sock = -1;
    for (int i = 0; i < MAX_RETRIES; i++) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            return 1;
        }

        /* TCP_NODELAY: no nagle buffering — send immediately */
        int one = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            break;

        close(sock);
        sock = -1;

        if (errno == ECONNREFUSED) {
            /* usbipd is restarting; wait and retry */
            sleep_ms(RETRY_MS);
            continue;
        }
        /* Any other error is fatal */
        perror("connect");
        return 1;
    }

    if (sock < 0) {
        /* Could not connect after retries — treat as timeout, not crash */
        return 0;
    }

    /* ── send the fuzz payload ────────────────────────────────────── */
    ssize_t sent = send(sock, ibuf, (size_t)len, MSG_NOSIGNAL);

    if (sent < 0) {
        close(sock);
        if (errno == ECONNRESET || errno == EPIPE)
            return 1;   /* daemon crashed */
        return 0;
    }

    /*
     * Wait briefly for a response (or connection close).
     * If we get ECONNRESET the daemon crashed → return 1.
     */
    uint8_t rbuf[256];
    ssize_t r = recv(sock, rbuf, sizeof(rbuf), 0);
    close(sock);

    if (r < 0 && (errno == ECONNRESET || errno == EPIPE))
        return 1;

    return 0;
}
