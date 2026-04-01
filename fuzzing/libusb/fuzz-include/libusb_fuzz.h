#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#define FUZZ_BUF_MAX (1 << 16)

extern uint8_t g_fuzz_buf[FUZZ_BUF_MAX];
extern size_t  g_fuzz_len;
extern size_t  g_fuzz_offset;

static inline void fuzz_reset(const uint8_t *data, size_t size)
{
    size_t n = size < FUZZ_BUF_MAX ? size : FUZZ_BUF_MAX;
    memcpy(g_fuzz_buf, data, n);
    g_fuzz_len    = n;
    g_fuzz_offset = 0;
}
