/*
 * harness.h - shared AFL++/libFuzzer entry boilerplate for the libnfs harnesses.
 *
 * Each fuzz_*.c defines:  static int fuzz_one(const uint8_t *data, size_t size);
 *
 * Build modes (set by setup.sh):
 *   afl-clang-fast            -> persistent loop, reads from AFL shared memory
 *   clang -DNFS_FUZZ_STANDALONE -> reads files from argv, for crash replay/triage
 *   <libFuzzer>               -> LLVMFuzzerTestOneInput
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nfsc/libnfs-zdr.h"

/* Initialise a ZDR memory stream in DECODE mode over the fuzz buffer.
 * ZDR is libnfs's reimplementation of XDR. zdrmem_create takes a non-const
 * char *, but in DECODE mode it only reads from the buffer. We cast away
 * const-ness; the alternative is allocating + copying every iteration which
 * murders persistent-mode throughput. */
static inline void nfs_zdrmem_decode(ZDR *zdr, const uint8_t *data, size_t size)
{
    memset(zdr, 0, sizeof(*zdr));
    zdrmem_create(zdr, (char *)(uintptr_t)data,
                  size > 0xffffffff ? 0xffffffff : (uint32_t)size,
                  ZDR_DECODE);
}

static int fuzz_one(const uint8_t *data, size_t size);

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
int main(void)
{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000))
        fuzz_one(buf, (size_t)__AFL_FUZZ_TESTCASE_LEN);
    return 0;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one(data, size);
}
#ifdef NFS_FUZZ_STANDALONE
int main(int argc, char **argv)
{
    static unsigned char buf[1 << 20];
    int i;
    for (i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        size_t n;
        if (!f)
            continue;
        n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        fprintf(stderr, "[*] %s (%zu bytes)\n", argv[i], n);
        fuzz_one(buf, n);
    }
    return 0;
}
#endif
#endif
