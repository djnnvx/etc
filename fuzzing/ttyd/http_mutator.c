/*
 * AFL++ Custom Mutator for TTYD HTTP fuzzing
 *
 * Understands the structured input format used by fuzz_http_parsing:
 *   [auth_mode:1][cred_len:2 BE][credential][path_len:2 BE][path][auth_header_value]
 *
 * Instead of random byte flips (which mostly break the format envelope),
 * this mutator makes semantically meaningful changes:
 *   - Swaps URL paths to known ttyd endpoints or traversal payloads
 *   - Mutates auth header values (scheme, base64, truncation)
 *   - Toggles auth modes
 *   - Varies credential content and length
 *
 * Build:
 *   afl-clang-fast -shared -fPIC -O2 -o http_mutator.so http_mutator.c
 *
 * Use:
 *   AFL_CUSTOM_MUTATOR_LIBRARY=./http_mutator.so afl-fuzz ...
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* AFL++ types */
typedef unsigned char u8;
typedef uint32_t u32;
typedef struct afl_state afl_state_t;

/* ── mutator state ──────────────────────────────────────────────────────── */

typedef struct {
    u8     *out_buf;
    size_t  out_buf_size;
    u32     seed;
} http_mutator_t;

/* ── interesting values ─────────────────────────────────────────────────── */

static const char *interesting_paths[] = {
    "/",
    "/ws",
    "/token",
    "/base-path",
    "/base-path/",
    "/../../../etc/passwd",
    "//etc/passwd",
    "/./../.././etc/shadow",
    "/%00/token",
    "/token%00.html",
    "/ws/../token",
    "/%2e%2e/%2e%2e/etc/passwd",
    "/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "",
    "/\r\nInjected: header",
    "/\x00hidden",
    "/%s%s%s%s%n",
    "/token?arg=;id",
    "/ws?arg=test&arg=another",
    "///",
};
#define N_PATHS (sizeof(interesting_paths) / sizeof(interesting_paths[0]))

static const char *interesting_auth[] = {
    "Basic YWRtaW46cGFzcw==",
    "Basic ",
    "Basic AAAA",
    "Basic ====",
    "Basic YWRtaW46",
    "Bearer token123",
    "Digest username=\"admin\"",
    "",
    "Basic \x00hidden",
    "BASIC YWRtaW46cGFzcw==",
    "basic YWRtaW46cGFzcw==",
    "Basic  YWRtaW46cGFzcw==",
    " Basic YWRtaW46cGFzcw==",
    "Basic\tYWRtaW46cGFzcw==",
    "Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "Basic %s%s%s%n%n",
    "X-Auth-User: admin",
};
#define N_AUTH (sizeof(interesting_auth) / sizeof(interesting_auth[0]))

static const char *interesting_creds[] = {
    "admin:pass",
    "YWRtaW46cGFzcw==",
    "",
    "AAAA",
    "a]very:long:credential:with:many:colons",
    "admin",
    ":nouser",
    "user:",
    ":",
};
#define N_CREDS (sizeof(interesting_creds) / sizeof(interesting_creds[0]))

/* ── helpers ────────────────────────────────────────────────────────────── */

static u32 rand_next(http_mutator_t *m) {
    m->seed = m->seed * 1103515245 + 12345;
    return (m->seed >> 16) & 0x7fff;
}

static size_t build_input(u8 *out, size_t max_size,
                          u8 auth_mode, const char *cred,
                          const char *path, const char *auth_hdr) {
    size_t cred_len = cred ? strlen(cred) : 0;
    size_t path_len = path ? strlen(path) : 0;
    size_t auth_len = auth_hdr ? strlen(auth_hdr) : 0;

    /* Cap lengths to prevent overflow */
    if (cred_len > 0xFFFF) cred_len = 0xFFFF;
    if (path_len > 0xFFFF) path_len = 0xFFFF;

    size_t total = 1 + 2 + cred_len + 2 + path_len + auth_len;
    if (total > max_size) {
        /* Trim auth_hdr to fit */
        if (1 + 2 + cred_len + 2 + path_len >= max_size) return 0;
        auth_len = max_size - 1 - 2 - cred_len - 2 - path_len;
        total = max_size;
    }

    size_t off = 0;
    out[off++] = auth_mode;
    out[off++] = (u8)(cred_len >> 8);
    out[off++] = (u8)(cred_len & 0xFF);
    if (cred_len > 0) { memcpy(out + off, cred, cred_len); off += cred_len; }
    out[off++] = (u8)(path_len >> 8);
    out[off++] = (u8)(path_len & 0xFF);
    if (path_len > 0) { memcpy(out + off, path, path_len); off += path_len; }
    if (auth_len > 0) { memcpy(out + off, auth_hdr, auth_len); off += auth_len; }

    return off;
}

/* Try to parse the structured format. Returns 0 on failure. */
static int parse_input(const u8 *buf, size_t buf_size,
                       u8 *auth_mode, const u8 **cred, size_t *cred_len,
                       const u8 **path, size_t *path_len,
                       const u8 **auth_hdr, size_t *auth_hdr_len) {
    if (buf_size < 5) return 0;

    *auth_mode = buf[0];
    *cred_len = (size_t)((buf[1] << 8) | buf[2]);
    size_t off = 3;

    if (*cred_len > buf_size - off - 2) return 0;
    *cred = buf + off;
    off += *cred_len;

    if (off + 2 > buf_size) return 0;
    *path_len = (size_t)((buf[off] << 8) | buf[off + 1]);
    off += 2;

    if (*path_len > buf_size - off) return 0;
    *path = buf + off;
    off += *path_len;

    *auth_hdr = buf + off;
    *auth_hdr_len = buf_size - off;

    return 1;
}

/* ── AFL++ custom mutator API ───────────────────────────────────────────── */

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    http_mutator_t *m = calloc(1, sizeof(http_mutator_t));
    if (!m) return NULL;
    m->out_buf_size = 1 << 16;
    m->out_buf = malloc(m->out_buf_size);
    if (!m->out_buf) { free(m); return NULL; }
    m->seed = seed;
    return m;
}

size_t afl_custom_fuzz(void *data, u8 *buf, size_t buf_size,
                       u8 **out_buf, u8 *add_buf, size_t add_buf_size,
                       size_t max_size) {
    http_mutator_t *m = (http_mutator_t *)data;

    if (max_size > m->out_buf_size) {
        m->out_buf = realloc(m->out_buf, max_size);
        if (!m->out_buf) { m->out_buf_size = 0; *out_buf = buf; return buf_size; }
        m->out_buf_size = max_size;
    }

    /* Parse the existing input */
    u8 auth_mode;
    const u8 *cred, *path, *auth_hdr;
    size_t cred_len, path_len, auth_hdr_len;

    int parsed = parse_input(buf, buf_size, &auth_mode, &cred, &cred_len,
                             &path, &path_len, &auth_hdr, &auth_hdr_len);

    /* Copy current fields into mutable buffers */
    static char m_cred[4096], m_path[4096], m_auth[4096];
    u8 m_mode;

    if (parsed) {
        m_mode = auth_mode % 3;
        size_t n;
        n = cred_len < sizeof(m_cred) - 1 ? cred_len : sizeof(m_cred) - 1;
        memcpy(m_cred, cred, n); m_cred[n] = '\0';
        n = path_len < sizeof(m_path) - 1 ? path_len : sizeof(m_path) - 1;
        memcpy(m_path, path, n); m_path[n] = '\0';
        n = auth_hdr_len < sizeof(m_auth) - 1 ? auth_hdr_len : sizeof(m_auth) - 1;
        memcpy(m_auth, auth_hdr, n); m_auth[n] = '\0';
    } else {
        /* Can't parse — generate a fresh valid input */
        m_mode = rand_next(m) % 3;
        strcpy(m_path, interesting_paths[rand_next(m) % N_PATHS]);
        strcpy(m_auth, interesting_auth[rand_next(m) % N_AUTH]);
        strcpy(m_cred, interesting_creds[rand_next(m) % N_CREDS]);
    }

    /* Pick a mutation strategy */
    u32 strategy = rand_next(m) % 8;

    switch (strategy) {
    case 0:
        /* Replace path with an interesting one */
        strcpy(m_path, interesting_paths[rand_next(m) % N_PATHS]);
        break;

    case 1:
        /* Replace auth header with an interesting one */
        strcpy(m_auth, interesting_auth[rand_next(m) % N_AUTH]);
        break;

    case 2:
        /* Toggle auth mode */
        m_mode = rand_next(m) % 3;
        if (m_mode == 1 && m_cred[0] == '\0')
            strcpy(m_cred, interesting_creds[rand_next(m) % N_CREDS]);
        break;

    case 3:
        /* Replace credential */
        strcpy(m_cred, interesting_creds[rand_next(m) % N_CREDS]);
        break;

    case 4: {
        /* Byte-level mutation on the path */
        size_t plen = strlen(m_path);
        if (plen > 0) {
            size_t pos = rand_next(m) % plen;
            m_path[pos] ^= (1 << (rand_next(m) % 8));
        }
        break;
    }

    case 5: {
        /* Byte-level mutation on the auth header */
        size_t alen = strlen(m_auth);
        if (alen > 0) {
            size_t pos = rand_next(m) % alen;
            m_auth[pos] ^= (1 << (rand_next(m) % 8));
        }
        break;
    }

    case 6: {
        /* Splice path from add_buf if available */
        if (add_buf && add_buf_size >= 5) {
            u8 am2; const u8 *c2, *p2, *a2;
            size_t cl2, pl2, al2;
            if (parse_input(add_buf, add_buf_size, &am2, &c2, &cl2,
                            &p2, &pl2, &a2, &al2) && pl2 > 0) {
                size_t n = pl2 < sizeof(m_path) - 1 ? pl2 : sizeof(m_path) - 1;
                memcpy(m_path, p2, n);
                m_path[n] = '\0';
            }
        }
        break;
    }

    case 7: {
        /* Mutate everything at once — max chaos while keeping structure */
        m_mode = rand_next(m) % 3;
        strcpy(m_path, interesting_paths[rand_next(m) % N_PATHS]);
        strcpy(m_auth, interesting_auth[rand_next(m) % N_AUTH]);
        if (m_mode == 1)
            strcpy(m_cred, interesting_creds[rand_next(m) % N_CREDS]);
        break;
    }
    }

    /* Rebuild the structured output */
    size_t out_len = build_input(m->out_buf, max_size,
                                 m_mode, m_cred, m_path, m_auth);
    if (out_len == 0) {
        /* Fallback: pass through original */
        *out_buf = buf;
        return buf_size;
    }

    *out_buf = m->out_buf;
    return out_len;
}

void afl_custom_deinit(void *data) {
    http_mutator_t *m = (http_mutator_t *)data;
    if (m) {
        free(m->out_buf);
        free(m);
    }
}
