#ifndef LIBUSB_FUZZ_CONFIG_H
#define LIBUSB_FUZZ_CONFIG_H

#define VERSION              "1.0.29-fuzz"
#define PLATFORM_POSIX       1
#define HAVE_SYS_TIME_H      1
#define HAVE_CLOCK_GETTIME   1
#define HAVE_PIPE2           1
#define HAVE_NFDS_T          1
#define _GNU_SOURCE          1
#define DEFAULT_VISIBILITY   __attribute__((visibility("default")))
#define PRINTF_FORMAT(a, b)  __attribute__((__format__(__printf__, a, b)))

/* ENABLE_LOGGING intentionally not defined: libusbi.h's #ifdef branch skips
 * logging setup and all usbi_err/warn/dbg macros expand to (void)(ctx). */

#endif
