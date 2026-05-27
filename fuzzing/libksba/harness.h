/*
 * harness.h - shared AFL++/libFuzzer entry boilerplate for the libksba harnesses.
 *
 * Each fuzz_*.c includes this and defines:  static int fuzz_one(const uint8_t*, size_t);
 *
 * Build modes (set by setup.sh):
 *   afl-clang-fast            -> persistent loop, reads from AFL shared memory
 *   clang -DKSBA_FUZZ_STANDALONE -> reads files from argv, for crash replay/triage
 *   <libFuzzer>               -> LLVMFuzzerTestOneInput
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpg-error.h>
#include "ksba.h"

/* Bound on idx-style accessor loops so adversarial inputs can't spin forever
 * inside the harness; real hangs in the library still surface via afl -t. */
#define KSBA_FUZZ_MAXITER 256

static int fuzz_one(const uint8_t *data, size_t size);

/* Walk and free a ksba_name_t (GeneralNames), exercising the name accessors. */
static inline void drain_name(ksba_name_t nm)
{
    int i;
    if (!nm)
        return;
    for (i = 0; i < KSBA_FUZZ_MAXITER && ksba_name_enum(nm, i); i++) {
        char *uri = ksba_name_get_uri(nm, i);
        ksba_free(uri);
    }
    ksba_name_release(nm);
}

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
#ifdef KSBA_FUZZ_STANDALONE
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
