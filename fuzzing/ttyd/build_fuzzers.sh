#!/bin/bash
# Build TTYD fuzzing harnesses
#
# What this script does:
#   1. Installs build dependencies
#   2. Clones ttyd source + runs cmake (for validation & compile_commands.json)
#   3. Generates mock headers/stubs so ttyd's .c files compile without real lws/uv
#   4. Compiles instrumented ttyd objects (http.c, protocol.c, utils.c)
#   5. Builds AFL++ harnesses that #include the real ttyd source files
#   6. Sets up AFL++ dictionaries (download from AFL++ repo, fall back to custom)
#   7. Generates seed corpus
#   8. Installs a crontab entry to back up crashes every 15 minutes
#
# Usage: ./build_fuzzers.sh [afl|libfuzzer]
#
# Note: gen-corpus.sh is merged into this script and is no longer separate.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-afl}"
SANITIZER="address,undefined"

TTYD_SRC="$SCRIPT_DIR/ttyd-src"
TTYD_OBJ="$SCRIPT_DIR/ttyd-obj"
FUZZ_INCLUDE="$SCRIPT_DIR/fuzz-include"
CRONTAB_MARKER="# ttyd-fuzz-crash-backup"
BACKUP_SCRIPT="$SCRIPT_DIR/backup_crashes.sh"

echo "[*] Building TTYD fuzzing harnesses"
echo "[*] Mode:      $MODE"
echo "[*] Sanitizer: $SANITIZER"
echo "[*] Script:    $SCRIPT_DIR"
echo

# ─── 1. dependency install ────────────────────────────────────────────────────

install_deps() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] Warning: Not running as root. Skipping apt-get installs."
        echo "    If builds fail, run: sudo apt-get install afl++ libjson-c-dev"
        echo "    cmake git libwebsockets-dev libuv1-dev pkg-config"
        return
    fi

    local DEPS="libjson-c-dev cmake git pkg-config"
    if [ "$MODE" = "afl" ]; then
        DEPS="$DEPS afl++"
    else
        DEPS="$DEPS clang"
    fi

    local MISSING=""
    for pkg in $DEPS; do
        dpkg -s "$pkg" &>/dev/null || MISSING="$MISSING $pkg"
    done

    if [ -n "$MISSING" ]; then
        echo "[*] Installing:$MISSING"
        apt-get install -y --no-install-recommends $MISSING
        echo "[+] Dependencies installed"
    fi

    # System tuning for AFL++
    if [ "$MODE" = "afl" ]; then
        local CORE_PATTERN
        CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "")
        if [[ "$CORE_PATTERN" == "|"* ]]; then
            echo core > /proc/sys/kernel/core_pattern
            echo "[+] core_pattern set to 'core'"
        fi
        for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            [ -f "$gov" ] && echo performance > "$gov" 2>/dev/null || true
        done
    fi
}

# ─── 2. clone + cmake ttyd ────────────────────────────────────────────────────

setup_ttyd_source() {
    # Clone
    if [ ! -d "$TTYD_SRC/.git" ]; then
        echo "[*] Cloning ttyd source..."
        git clone --depth=1 https://github.com/tsl0922/ttyd "$TTYD_SRC"
        echo "[+] Cloned ttyd to $TTYD_SRC"
    else
        echo "[*] ttyd source already present — pulling latest..."
        git -C "$TTYD_SRC" pull --ff-only 2>/dev/null || \
            echo "[!] Pull skipped (uncommitted local changes or offline)"
    fi

    # cmake configure (validates deps, produces compile_commands.json for IDEs)
    local BUILD_DIR="$TTYD_SRC/build"
    mkdir -p "$BUILD_DIR"
    echo "[*] Running cmake configure..."
    (
        cd "$BUILD_DIR"
        # Use the real compiler here (not AFL++) — this is only for validation/headers
        cmake -DCMAKE_BUILD_TYPE=Debug \
              -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
              .. 2>&1 | tail -5 || true
    )
    echo "[+] cmake done (compile_commands.json at $BUILD_DIR/compile_commands.json)"

    # ── generate mock headers ────────────────────────────────────────────────
    mkdir -p "$FUZZ_INCLUDE"

    # fuzz-include/libwebsockets.h  — replaces the real lws header when we
    # compile ttyd source files.  Covers all types/constants/functions used
    # by http.c and protocol.c.  Implementations live in fuzz_lws_mock.c.
    cat > "$FUZZ_INCLUDE/libwebsockets.h" <<'EOF'
#pragma once
/* Mock libwebsockets header for AFL++ fuzzing of ttyd.
 * Provides all types and function declarations used by http.c / protocol.c.
 * Runtime implementations are in fuzz_lws_mock.c.                         */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/* ── opaque types ──────────────────────────────────────────────────────── */
struct lws           { int _fd; };
struct lws_context   { int _dummy; };
struct lws_vhost     { int _dummy; };

typedef struct lws           lws_t;
typedef struct lws_context   lws_context;

/* ── callback reasons ──────────────────────────────────────────────────── */
typedef enum lws_callback_reasons {
    LWS_CALLBACK_HTTP = 0,
    LWS_CALLBACK_HTTP_WRITEABLE,
    LWS_CALLBACK_HTTP_FILE_COMPLETION,
    LWS_CALLBACK_HTTP_BIND_PROTOCOL,
    LWS_CALLBACK_FILTER_HTTP_CONNECTION,
    LWS_CALLBACK_CLOSED_HTTP,
    LWS_CALLBACK_ADD_HEADERS,
    LWS_CALLBACK_CHECK_ACCESS_RIGHTS,
    LWS_CALLBACK_PROCESS_HTML,
    LWS_CALLBACK_ESTABLISHED = 100,
    LWS_CALLBACK_CLOSED,
    LWS_CALLBACK_RECEIVE,
    LWS_CALLBACK_SERVER_WRITEABLE,
    LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
    LWS_CALLBACK_PROTOCOL_INIT,
    LWS_CALLBACK_PROTOCOL_DESTROY,
    LWS_CALLBACK_WS_PEER_INITIATED_CLOSE,
    LWS_CALLBACK_SESSION_INFO,
    _LWS_CALLBACK_DUMMY = 9999
} lws_callback_reasons;

/* ── write protocols ───────────────────────────────────────────────────── */
typedef enum lws_write_protocol {
    LWS_WRITE_TEXT = 0,
    LWS_WRITE_BINARY,
    LWS_WRITE_CONTINUATION,
    LWS_WRITE_HTTP,
    LWS_WRITE_PING,
    LWS_WRITE_PONG,
    LWS_WRITE_CLOSE,
    LWS_WRITE_HTTP_HEADERS,
    LWS_WRITE_HTTP_FINAL_HEADERS,
    _LWS_WRITE_DUMMY = 9999
} lws_write_protocol;

/* ── token indexes ─────────────────────────────────────────────────────── */
typedef enum lws_token_indexes {
    WSI_TOKEN_GET_URI = 0,
    WSI_TOKEN_POST_URI,
    WSI_TOKEN_OPTIONS_URI,
    WSI_TOKEN_HOST,
    WSI_TOKEN_CONNECTION,
    WSI_TOKEN_UPGRADE,
    WSI_TOKEN_ORIGIN,
    WSI_TOKEN_HTTP,
    WSI_TOKEN_HTTP_ACCEPT,
    WSI_TOKEN_HTTP_AUTHORIZATION,
    WSI_TOKEN_HTTP_COOKIE,
    WSI_TOKEN_HTTP_CONTENT_LENGTH,
    WSI_TOKEN_HTTP_CONTENT_TYPE,
    WSI_TOKEN_HTTP_RANGE,
    WSI_TOKEN_HTTP_REFERER,
    WSI_TOKEN_HTTP_COLON_AUTHORITY,
    WSI_TOKEN_HTTP_COLON_METHOD,
    WSI_TOKEN_HTTP_COLON_PATH,
    WSI_TOKEN_HTTP_COLON_SCHEME,
    WSI_TOKEN_HTTP_ACCEPT_ENCODING,
    WSI_TOKEN_HTTP_ACCEPT_LANGUAGE,
    WSI_TOKEN_HTTP_PRAGMA,
    WSI_TOKEN_HTTP_CACHE_CONTROL,
    WSI_TOKEN_HTTP_IF_MODIFIED_SINCE,
    WSI_TOKEN_HTTP_IF_NONE_MATCH,
    WSI_TOKEN_HTTP_TRANSFER_ENCODING,
    WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
    WSI_TOKEN_HTTP_PROXY_AUTHENTICATE,
    WSI_TOKEN_HTTP_PROXY_AUTHORIZATION,
    WSI_TOKEN_HTTP_X_FORWARDED_FOR,
    WSI_TOKEN_HTTP_URI_ARGS,
    WSI_TOKEN_COLON_STATUS,
    WSI_TOKEN_HTTP_ACCEPT_RANGES,
    WSI_TOKEN_HTTP_LOCATION,
    WSI_TOKEN_HTTP_CONTENT_RANGE,
    WSI_TOKEN_HTTP_SET_COOKIE,
    WSI_TOKEN_HTTP_CONTENT_DISPOSITION,
    WSI_TOKEN_HTTP_CONTENT_ENCODING,
    WSI_TOKEN_HTTP_CONTENT_LANGUAGE,
    WSI_TOKEN_HTTP_CONTENT_LOCATION,
    ARRAY_SIZE_WSI_TOKENS,
} lws_token_indexes;

/* ── HTTP status codes ─────────────────────────────────────────────────── */
#define HTTP_STATUS_OK                    200
#define HTTP_STATUS_NO_CONTENT            204
#define HTTP_STATUS_PARTIAL_CONTENT       206
#define HTTP_STATUS_MOVED_PERMANENTLY     301
#define HTTP_STATUS_FOUND                 302
#define HTTP_STATUS_NOT_MODIFIED          304
#define HTTP_STATUS_BAD_REQUEST           400
#define HTTP_STATUS_UNAUTHORIZED          401
#define HTTP_STATUS_FORBIDDEN             403
#define HTTP_STATUS_NOT_FOUND             404
#define HTTP_STATUS_PROXY_AUTH_REQUIRED   407
#define HTTP_STATUS_INTERNAL_SERVER_ERROR 500
#define HTTP_STATUS_NOT_IMPLEMENTED       501

/* ── misc types ────────────────────────────────────────────────────────── */
typedef uint64_t lws_filepos_t;

/* ── misc constants ────────────────────────────────────────────────────── */
#define LWS_PRE 32
#define LWS_CLOSE_STATUS_NOSTATUS               0
#define LWS_CLOSE_STATUS_NORMAL                 1000
#define LWS_CLOSE_STATUS_POLICY_VIOLATION       1008
#define LWS_CLOSE_STATUS_UNEXPECTED_CONDITION   1011

typedef enum pending_timeout {
    NO_PENDING_TIMEOUT = 0,
    PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE,
    _PENDING_TIMEOUT_DUMMY = 100
} pending_timeout;

/* ── protocol registration (used in server.c, not in fuzzing target) ─── */
typedef int (*lws_callback_function)(struct lws *wsi,
                                     enum lws_callback_reasons reason,
                                     void *user, void *in, size_t len);
struct lws_protocols {
    const char            *name;
    lws_callback_function  callback;
    size_t                 per_session_data_size;
    size_t                 rx_buffer_size;
    unsigned int           id;
    void                  *user;
    size_t                 tx_packet_size;
};

struct lws_http_mount     { int _dummy; };
struct lws_context_creation_info { int _dummy; };

/* ── logging macros ────────────────────────────────────────────────────── */
#define lwsl_err(fmt, ...)    fprintf(stderr, "ERR: " fmt, ##__VA_ARGS__)
#define lwsl_warn(fmt, ...)   fprintf(stderr, "WRN: " fmt, ##__VA_ARGS__)
#define lwsl_notice(fmt, ...) do {} while (0)
#define lwsl_info(fmt, ...)   do {} while (0)
#define lwsl_debug(fmt, ...)  do {} while (0)
#define lwsl_user(fmt, ...)   do {} while (0)

/* ── function declarations (implementations in fuzz_lws_mock.c) ────────── */
int    lws_hdr_copy(struct lws *wsi, char *dest, int len,
                    enum lws_token_indexes h);
int    lws_hdr_custom_length(struct lws *wsi, const char *name, int nlen);
int    lws_hdr_custom_copy(struct lws *wsi, char *dst, int len,
                            const char *name, int nlen);
int    lws_hdr_copy_fragment(struct lws *wsi, char *dst, int len,
                              enum lws_token_indexes h, int frag_idx);
int    lws_return_http_status(struct lws *wsi, unsigned int code,
                               const char *html_body);
int    lws_add_http_header_status(struct lws *wsi, unsigned int code,
                                   unsigned char **p, unsigned char *end);
int    lws_add_http_header_content_length(struct lws *wsi,
                                           lws_filepos_t content_length,
                                           unsigned char **p,
                                           unsigned char *end);
int    lws_add_http_header_by_token(struct lws *wsi, enum lws_token_indexes h,
                                    const unsigned char *value, int length,
                                    unsigned char **p, unsigned char *end);
int    lws_add_http_header_by_name(struct lws *wsi, const unsigned char *name,
                                   const unsigned char *value, int length,
                                   unsigned char **p, unsigned char *end);
int    lws_finalize_http_header(struct lws *wsi, unsigned char **p,
                                 unsigned char *end);
int    lws_finalize_write_http_header(struct lws *wsi, unsigned char *start,
                                       unsigned char **p, unsigned char *end);
int    lws_write(struct lws *wsi, unsigned char *buf, size_t len,
                 enum lws_write_protocol protocol);
int    lws_callback_on_writable(struct lws *wsi);
void   lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs);
void   lws_close_reason(struct lws *wsi, int status,
                         unsigned char *buf, size_t len);
struct lws_context *lws_get_context(const struct lws *wsi);
int    lws_parse_uri(char *p, const char **prot, const char **host,
                     int *port, const char **path);
int    lws_is_final_fragment(struct lws *wsi);
size_t lws_remaining_packet_payload(struct lws *wsi);
int    lws_get_peer_simple(struct lws *wsi, char *name, size_t namelen);
int    lws_serve_http_file(struct lws *wsi, const char *file,
                            const char *content_type,
                            const char *other_headers, int other_headers_len);
int    lws_http_transaction_completed(struct lws *wsi);
struct lws_context *lws_create_context(struct lws_context_creation_info *info);
void   lws_context_destroy(struct lws_context *context);
int    lws_service(struct lws_context *context, int timeout_ms);
void   lws_cancel_service(struct lws_context *context);
void  *lws_wsi_user(struct lws *wsi);
struct lws *lws_get_network_wsi(struct lws *wsi);
int    lws_get_peer_write_allowance(struct lws *wsi);
int    lws_write_http(struct lws *wsi, void *buf, size_t len);
int    lws_send_pipe_choked(struct lws *wsi);
EOF
    echo "[+] Generated fuzz-include/libwebsockets.h"

    # fuzz-include/uv.h  — minimal libuv stubs (server.h and pty.h use uv types)
    cat > "$FUZZ_INCLUDE/uv.h" <<'EOF'
#pragma once
/* Minimal libuv stub for fuzzing ttyd — only types, no event loop. */
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct uv_loop_s       uv_loop_t;
typedef struct uv_handle_s     uv_handle_t;
typedef struct uv_async_s      uv_async_t;
typedef struct uv_pipe_s       uv_pipe_t;
typedef struct uv_timer_s      uv_timer_t;
typedef struct uv_thread_s     uv_thread_t;
typedef struct uv_mutex_s      uv_mutex_t;
typedef struct uv_process_s    uv_process_t;
typedef struct uv_signal_s     uv_signal_t;

struct uv_loop_s   { void *data; };
struct uv_handle_s { void *data; uv_loop_t *loop; };
struct uv_async_s  { void *data; uv_loop_t *loop; };
struct uv_pipe_s   { void *data; uv_loop_t *loop; };
struct uv_timer_s  { void *data; uv_loop_t *loop; };
struct uv_thread_s { unsigned long _tid; };
struct uv_mutex_s  { int _m; };
struct uv_process_s{ void *data; };
struct uv_signal_s { void *data; };

typedef void (*uv_close_cb)(uv_handle_t *handle);
typedef void (*uv_async_cb)(uv_async_t *handle);
typedef void (*uv_alloc_cb)(uv_handle_t *handle, size_t suggested_size, void *buf);
typedef void (*uv_read_cb)(uv_pipe_t *stream, ssize_t nread, const void *buf);
typedef void (*uv_exit_cb)(uv_process_t *process, int64_t exit_status, int term_signal);
typedef void (*uv_walk_cb)(uv_handle_t *handle, void *arg);
typedef void (*uv_thread_cb)(void *arg);
typedef void (*uv_timer_cb)(uv_timer_t *handle);

#define UV_RUN_DEFAULT 0
#define UV_RUN_ONCE    1
#define UV_RUN_NOWAIT  2

static inline int   uv_loop_init(uv_loop_t *l)               { return 0; }
static inline int   uv_run(uv_loop_t *l, int mode)            { return 0; }
static inline void  uv_stop(uv_loop_t *l)                     {}
static inline int   uv_loop_close(uv_loop_t *l)               { return 0; }
static inline void  uv_close(uv_handle_t *h, uv_close_cb cb)  {}
static inline int   uv_async_init(uv_loop_t *l, uv_async_t *a, uv_async_cb cb) { a->loop = l; return 0; }
static inline int   uv_async_send(uv_async_t *a)              { return 0; }
static inline int   uv_timer_init(uv_loop_t *l, uv_timer_t *t){ return 0; }
static inline int   uv_timer_start(uv_timer_t *t, uv_timer_cb cb, uint64_t timeout, uint64_t repeat) { return 0; }
static inline int   uv_timer_stop(uv_timer_t *t)              { return 0; }
static inline int   uv_mutex_init(uv_mutex_t *m)              { return 0; }
static inline void  uv_mutex_lock(uv_mutex_t *m)              {}
static inline void  uv_mutex_unlock(uv_mutex_t *m)            {}
static inline void  uv_mutex_destroy(uv_mutex_t *m)           {}
static inline int   uv_thread_create(uv_thread_t *t, uv_thread_cb cb, void *arg) { return 0; }
static inline int   uv_thread_join(uv_thread_t *t)            { return 0; }
static inline uv_loop_t *uv_default_loop(void)                { return NULL; }
static inline int          uv_walk(uv_loop_t *l, uv_walk_cb cb, void *arg) { return 0; }
static inline const char  *uv_err_name(int err)   { return "UNKNOWN"; }
static inline const char  *uv_strerror(int err)   { return "unknown error"; }
EOF
    echo "[+] Generated fuzz-include/uv.h"

    # fuzz_lws_mock.h  — declares fuzzer-controlled lws state, included by harnesses
    cat > "$SCRIPT_DIR/fuzz_lws_mock.h" <<'EOF'
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Fuzzer-controlled header values.  Set these before calling any ttyd
 * function that reads HTTP headers; the mock lws_hdr_* functions return
 * whatever is stored here.                                                 */
extern char _fuzz_auth_header[4096];
extern int  _fuzz_auth_header_len;
extern char _fuzz_custom_header[4096];
extern int  _fuzz_custom_header_len;

/* Reset all mock state — call at the start of every fuzz iteration. */
void fuzz_lws_reset(void);

/* Convenience setters. */
static inline void fuzz_lws_set_auth(const char *v, int len) {
    int n = len < 4095 ? len : 4095;
    memcpy(_fuzz_auth_header, v, n);
    _fuzz_auth_header[n] = '\0';
    _fuzz_auth_header_len = n;
}
static inline void fuzz_lws_set_custom(const char *v, int len) {
    int n = len < 4095 ? len : 4095;
    memcpy(_fuzz_custom_header, v, n);
    _fuzz_custom_header[n] = '\0';
    _fuzz_custom_header_len = n;
}
EOF
    echo "[+] Generated fuzz_lws_mock.h"

    # fuzz_lws_mock.c  — runtime implementations of the mocked lws functions
    cat > "$SCRIPT_DIR/fuzz_lws_mock.c" <<'EOF'
/* Mock implementations of libwebsockets runtime functions for fuzzing ttyd.
 * lws_hdr_copy / lws_hdr_custom_* return fuzzer-controlled data so AFL++
 * can drive the auth logic.  All other lws functions are safe no-ops.      */

#include "fuzz-include/libwebsockets.h"
#include "fuzz_lws_mock.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* ── fuzzer-controlled state ─────────────────────────────────────────── */
char _fuzz_auth_header[4096];
int  _fuzz_auth_header_len;
char _fuzz_custom_header[4096];
int  _fuzz_custom_header_len;

void fuzz_lws_reset(void) {
    memset(_fuzz_auth_header,   0, sizeof(_fuzz_auth_header));
    _fuzz_auth_header_len   = 0;
    memset(_fuzz_custom_header, 0, sizeof(_fuzz_custom_header));
    _fuzz_custom_header_len = 0;
}

/* ── header accessors ────────────────────────────────────────────────── */
int lws_hdr_copy(struct lws *wsi, char *dest, int len,
                 enum lws_token_indexes h) {
    const char *src = NULL;
    int srclen = 0;
    if (h == WSI_TOKEN_HTTP_AUTHORIZATION) {
        src    = _fuzz_auth_header;
        srclen = _fuzz_auth_header_len;
    }
    if (!src || !dest || len <= 0) { if (dest && len > 0) dest[0] = '\0'; return 0; }
    int n = srclen < len - 1 ? srclen : len - 1;
    memcpy(dest, src, n);
    dest[n] = '\0';
    return n;
}

int lws_hdr_custom_length(struct lws *wsi, const char *name, int nlen) {
    return _fuzz_custom_header_len;
}

int lws_hdr_custom_copy(struct lws *wsi, char *dst, int len,
                         const char *name, int nlen) {
    if (!dst || len <= 0) return 0;
    int n = _fuzz_custom_header_len < len - 1 ? _fuzz_custom_header_len : len - 1;
    memcpy(dst, _fuzz_custom_header, n);
    dst[n] = '\0';
    return n;
}

int lws_hdr_copy_fragment(struct lws *wsi, char *dst, int len,
                           enum lws_token_indexes h, int frag_idx) {
    if (dst && len > 0) dst[0] = '\0';
    return 0;
}

/* ── URI parsing ─────────────────────────────────────────────────────── */
int lws_parse_uri(char *p, const char **prot, const char **host,
                  int *port, const char **path) {
    if (prot)  *prot  = "";
    if (host)  *host  = "";
    if (port)  *port  = 0;
    if (path)  *path  = p ? p : "";
    return 0;
}

/* ── HTTP response helpers — all no-ops for fuzzing ─────────────────── */
int lws_return_http_status(struct lws *wsi, unsigned int code,
                            const char *html_body) { return 0; }
int lws_add_http_header_status(struct lws *wsi, unsigned int code,
                                unsigned char **p, unsigned char *end) { return 0; }
int lws_add_http_header_content_length(struct lws *wsi, lws_filepos_t content_length,
                                        unsigned char **p, unsigned char *end) { return 0; }
int lws_add_http_header_by_token(struct lws *wsi, enum lws_token_indexes h,
                                  const unsigned char *v, int len,
                                  unsigned char **p, unsigned char *end) { return 0; }
int lws_add_http_header_by_name(struct lws *wsi, const unsigned char *n,
                                 const unsigned char *v, int len,
                                 unsigned char **p, unsigned char *end) { return 0; }
int lws_finalize_http_header(struct lws *wsi, unsigned char **p,
                              unsigned char *end) { return 0; }
int lws_finalize_write_http_header(struct lws *wsi, unsigned char *start,
                                    unsigned char **p, unsigned char *end) { return 0; }
int lws_write(struct lws *wsi, unsigned char *buf, size_t len,
              enum lws_write_protocol protocol) { return (int)len; }
int lws_callback_on_writable(struct lws *wsi) { return 0; }
void lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs) {}
void lws_close_reason(struct lws *wsi, int status,
                       unsigned char *buf, size_t len) {}
struct lws_context *lws_get_context(const struct lws *wsi) { return NULL; }
int lws_is_final_fragment(struct lws *wsi) { return 1; }
size_t lws_remaining_packet_payload(struct lws *wsi) { return 0; }
int lws_get_peer_simple(struct lws *wsi, char *name, size_t namelen) {
    if (name && namelen > 0) { strncpy(name, "127.0.0.1", namelen - 1); name[namelen-1] = '\0'; }
    return 0;
}
int lws_serve_http_file(struct lws *wsi, const char *file,
                         const char *content_type, const char *other_headers,
                         int other_headers_len) { return 0; }
int lws_http_transaction_completed(struct lws *wsi) { return 0; }
struct lws_context *lws_create_context(struct lws_context_creation_info *i) { return NULL; }
void lws_context_destroy(struct lws_context *ctx) {}
int lws_service(struct lws_context *ctx, int timeout_ms) { return 0; }
void lws_cancel_service(struct lws_context *ctx) {}
void *lws_wsi_user(struct lws *wsi) { return NULL; }
struct lws *lws_get_network_wsi(struct lws *wsi) { return wsi; }
int lws_get_peer_write_allowance(struct lws *wsi) { return -1; }
int lws_write_http(struct lws *wsi, void *buf, size_t len) { return (int)len; }
int lws_send_pipe_choked(struct lws *wsi) { return 0; }
EOF
    echo "[+] Generated fuzz_lws_mock.c"

    # mock_server_globals.c  — provides the global `struct server *server`
    # expected by http.c and protocol.c
    cat > "$SCRIPT_DIR/mock_server_globals.c" <<'EOF'
/* Provides globals that ttyd's http.c and protocol.c reference.
 * Normally defined in main.c; here we provide stub definitions.
 * Fuzzing harnesses call fuzz_server_reset() before each iteration.       */

#include "fuzz-include/libwebsockets.h"
#include "fuzz-include/uv.h"
#include "ttyd-src/src/server.h"
#include <string.h>

/* Globals declared extern in server.h */
struct server        *server    = NULL;
struct lws_context   *context   = NULL;
volatile bool         force_exit = false;
struct endpoints      endpoints  = {"/ws", "/", "/token", "/"};

/* Fuzzer-private server instance */
struct server  _fuzz_server;

void fuzz_server_reset(void) {
    memset(&_fuzz_server, 0, sizeof(_fuzz_server));
    _fuzz_server.writable      = true;
    _fuzz_server.check_origin  = false;
    _fuzz_server.max_clients   = 0;
    server    = &_fuzz_server;
    context   = NULL;
    force_exit = false;
}
EOF
    echo "[+] Generated mock_server_globals.c"

    # mock_pty_stubs.c  — stubs for PTY functions called by protocol.c
    # Prevents actual process spawning during fuzzing
    cat > "$SCRIPT_DIR/mock_pty_stubs.c" <<'EOF'
/* Stub implementations of PTY functions used by ttyd's protocol.c.
 * All functions are no-ops so no real processes are ever launched during
 * fuzzing.  Signatures match pty.h exactly.                               */

#include "fuzz-include/libwebsockets.h"
#include "fuzz-include/uv.h"
#include "ttyd-src/src/server.h"
#include "ttyd-src/src/pty.h"
#include <stdlib.h>
#include <string.h>

pty_buf_t *pty_buf_init(char *base, size_t len)         { return NULL; }
void       pty_buf_free(pty_buf_t *buf)                  {}
pty_process *process_init(void *ctx, uv_loop_t *loop,
                           char *argv[], char *envp[])   { return calloc(1, sizeof(pty_process)); }
bool       process_running(pty_process *process)         { return false; }
void       process_free(pty_process *process)            { free(process); }
int        pty_spawn(pty_process *process,
                     pty_read_cb read_cb,
                     pty_exit_cb exit_cb)                { return -1; }
void       pty_pause(pty_process *process)               {}
void       pty_resume(pty_process *process)              {}
int        pty_write(pty_process *process,
                     pty_buf_t *buf)                     { return -1; }
bool       pty_resize(pty_process *process)              { return false; }
bool       pty_kill(pty_process *process, int sig)       { return false; }
EOF
    echo "[+] Generated mock_pty_stubs.c"

    # ── compile instrumented ttyd objects ────────────────────────────────
    mkdir -p "$TTYD_OBJ"
    local JSON_CFLAGS
    JSON_CFLAGS=$(pkg-config --cflags json-c 2>/dev/null || echo "")

    local OBJ_CC OBJ_CFLAGS
    if [ "$MODE" = "afl" ]; then
        OBJ_CC="afl-clang-fast"
    else
        OBJ_CC="clang"
    fi
    OBJ_CFLAGS="-fsanitize=$SANITIZER -g -O1 -D_GNU_SOURCE -std=gnu99"
    OBJ_CFLAGS="$OBJ_CFLAGS -I$FUZZ_INCLUDE -I$TTYD_SRC/src $JSON_CFLAGS"
    # Suppress warnings from upstream code we don't control
    OBJ_CFLAGS="$OBJ_CFLAGS -Wno-implicit-function-declaration -Wno-int-conversion"

    echo
    echo "[*] Compiling instrumented ttyd objects..."
    # Only utils.c is pre-compiled as a shared object.
    # http.c and protocol.c are compiled directly into each harness via
    # #include — pre-compiling them here would cause multiple-definition
    # linker errors.
    for src in utils; do
        echo "    $src.c → ttyd-obj/$src.o"
        $OBJ_CC $OBJ_CFLAGS -c "$TTYD_SRC/src/$src.c" -o "$TTYD_OBJ/$src.o"
    done

    # Mock objects
    for src in fuzz_lws_mock mock_server_globals mock_pty_stubs; do
        echo "    $src.c → ttyd-obj/$src.o"
        $OBJ_CC $OBJ_CFLAGS -c "$SCRIPT_DIR/$src.c" -o "$TTYD_OBJ/$src.o"
    done

    echo "[+] ttyd objects compiled to $TTYD_OBJ/"
}

# ─── 3. dictionaries ──────────────────────────────────────────────────────────

setup_dictionaries() {
    local DICT_DIR="$SCRIPT_DIR/dictionaries"
    mkdir -p "$DICT_DIR"

    # Try system AFL++ dictionaries first
    for sys_dir in /usr/share/afl++/dictionaries /usr/local/share/afl++/dictionaries; do
        if [ -d "$sys_dir" ]; then
            [ -f "$sys_dir/http.dict" ] && [ ! -f "$DICT_DIR/http.dict" ] && \
                cp "$sys_dir/http.dict" "$DICT_DIR/http.dict" && \
                echo "[+] Copied http.dict from $sys_dir"
            [ -f "$sys_dir/json.dict" ] && [ ! -f "$DICT_DIR/json.dict" ] && \
                cp "$sys_dir/json.dict" "$DICT_DIR/json.dict" && \
                echo "[+] Copied json.dict from $sys_dir"
            break
        fi
    done

    # Download from AFL++ GitHub if still missing (http.dict and json.dict
    # ship under those exact names in the AFL++ stable branch)
    local BASE="https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/dictionaries"
    local DL=""
    command -v wget  &>/dev/null && DL="wget -q -O"
    command -v curl  &>/dev/null && [ -z "$DL" ] && DL="curl -fsSL -o"

    for dict in http json; do
        if [ ! -f "$DICT_DIR/$dict.dict" ] && [ -n "$DL" ]; then
            echo "[*] Downloading $dict.dict from AFL++ repo..."
            $DL "$DICT_DIR/$dict.dict" "$BASE/$dict.dict" && \
                echo "[+] Downloaded $dict.dict" || \
                rm -f "$DICT_DIR/$dict.dict"
        fi
    done

    # Minimal fallback if still missing
    if [ ! -f "$DICT_DIR/http.dict" ]; then
        cat > "$DICT_DIR/http.dict" <<'DICT'
"Basic "
"Bearer "
"Authorization: Basic "
"Origin: "
"Host: "
"GET "
"POST "
"HTTP/1.1"
"\r\n\r\n"
"X-Auth-User"
"Upgrade: websocket"
"Sec-WebSocket-Version: 13"
DICT
        echo "[+] Created dictionaries/http.dict (fallback)"
    fi

    if [ ! -f "$DICT_DIR/json.dict" ]; then
        cat > "$DICT_DIR/json.dict" <<'DICT'
"{"
"}"
"null"
"true"
"false"
"\"columns\":"
"\"rows\":"
"\"AuthToken\":"
DICT
        echo "[+] Created dictionaries/json.dict (fallback)"
    fi

    echo "[+] Dictionaries: $(ls "$DICT_DIR")"
}

# ─── 4. corpus generation (formerly gen-corpus.sh) ───────────────────────────

generate_corpus() {
    mkdir -p "$SCRIPT_DIR/corpus/auth_header"
    mkdir -p "$SCRIPT_DIR/corpus/websocket_auth"
    mkdir -p "$SCRIPT_DIR/corpus/http_parsing"

    # ── auth_header ──────────────────────────────────────────────────────────
    # Format: [mode:1][credential_len:2 BE][credential][auth_header_value]
    echo "[*] Generating corpus/auth_header/"
    local D="$SCRIPT_DIR/corpus/auth_header"

    printf '\x00\x00\x00anything-goes'                         > "$D/noauth_basic"
    printf '\x00\x00\x00'                                      > "$D/noauth_empty"
    printf '\x00\x00\x00Basic YWRtaW46cGFzcw=='               > "$D/noauth_with_basic"
    printf '\x01\x00\x0badmin:pass\x00Basic YWRtaW46cGFzcw==' > "$D/basic_valid"
    printf '\x01\x00\x0badmin:pass\x00Basic INVALIDBASE64=='   > "$D/basic_mismatch"
    printf '\x01\x00\x0badmin:pass\x00Basic '                  > "$D/basic_empty_token"
    printf '\x01\x00\x0badmin:pass\x00'                        > "$D/basic_no_header"
    printf '\x01\x00\x0badmin:pass\x00Bearer token123'         > "$D/basic_wrong_scheme"
    printf '\x01\x00\x0badmin:pass\x00basic YWRtaW46cGFzcw==' > "$D/basic_lowercase"
    printf '\x01\x00\x00\x00Basic YWRtaW46cGFzcw=='           > "$D/basic_no_credential"
    printf '\x02\x00\x00some-token-value'                      > "$D/custom_with_value"
    printf '\x02\x00\x00'                                      > "$D/custom_empty"
    printf '\x01\x00\x0badmin:pass\x00BASIC YWRtaW46cGFzcw==' > "$D/basic_uppercase"
    printf '\x01\x00\x0badmin:pass\x00bAsIc YWRtaW46cGFzcw==' > "$D/basic_mixedcase"
    printf '\x01\x00\x02a:\x00Basic YTo='                      > "$D/basic_b64_pad1"
    printf '\x01\x00\x01a\x00Basic YQ=='                       > "$D/basic_b64_pad2"
    printf '\x01\x00\x01:\x00Basic Og=='                       > "$D/basic_colon_only"
    printf '\x01\x00\x0badmin:pass\x00Basic  YWRtaW46cGFzcw==' > "$D/basic_double_space"
    printf '\x01\x00\x0badmin:pass\x00 Basic YWRtaW46cGFzcw==' > "$D/basic_leading_space"
    python3 -c "
import sys
cred = b'A' * 255 + b':' + b'B' * 255
hdr  = b'\x01' + len(cred).to_bytes(2,'big') + cred + b'Basic ' + b'A'*500
sys.stdout.buffer.write(hdr)
" > "$D/basic_long_cred"
    python3 -c "
import sys
cred  = b'x:y'
hdr   = b'Basic ' + b'A' * 248
sys.stdout.buffer.write(b'\x01' + len(cred).to_bytes(2,'big') + cred + hdr)
" > "$D/boundary_254"
    python3 -c "
import sys
cred  = b'x:y'
hdr   = b'Basic ' + b'A' * 250
sys.stdout.buffer.write(b'\x01' + len(cred).to_bytes(2,'big') + cred + hdr)
" > "$D/boundary_256"
    python3 -c "
import sys
cred  = b'x:y'
hdr   = b'Basic ' + b'A' * 251
sys.stdout.buffer.write(b'\x01' + len(cred).to_bytes(2,'big') + cred + hdr)
" > "$D/boundary_257"
    echo "[+] Generated $(ls "$D" | wc -l) seeds for auth_header"

    # ── websocket_auth ───────────────────────────────────────────────────────
    # Format: [has_credential:1][credential_len:2 BE][credential][json_message]
    echo "[*] Generating corpus/websocket_auth/"
    local W="$SCRIPT_DIR/corpus/websocket_auth"

    printf '\x00\x00\x00{"columns":80,"rows":24}'                              > "$W/noauth_normal"
    printf '\x00\x00\x00{"columns":200,"rows":50}'                             > "$W/noauth_large_term"
    printf '\x00\x00\x00{}'                                                    > "$W/noauth_empty_json"
    printf '\x00\x00\x00{"columns":80,"rows":24,"AuthToken":"ignored"}'        > "$W/noauth_with_token"
    printf '\x01\x00\x05admin{"columns":80,"rows":24,"AuthToken":"admin"}'     > "$W/auth_valid"
    printf '\x01\x00\x05admin{"columns":80,"rows":24,"AuthToken":"wrong"}'     > "$W/auth_invalid"
    printf '\x01\x00\x05admin{"columns":80,"rows":24}'                         > "$W/auth_missing_token"
    printf '\x01\x00\x05admin{"AuthToken":"admin"}'                            > "$W/auth_no_dimensions"
    printf '\x01\x00\x00{"columns":80,"rows":24}'                              > "$W/auth_empty_cred"
    printf '\x00\x00\x00{invalid json}'                                        > "$W/json_malformed"
    printf '\x00\x00\x00{"columns":'                                           > "$W/json_truncated"
    printf '\x00\x00\x00'                                                      > "$W/json_empty"
    printf '\x01\x00\x03foo[1,2,3]'                                            > "$W/json_array"
    printf '\x00\x00\x00{"columns":99999,"rows":99999}'                        > "$W/json_huge_values"
    printf '\x00\x00\x00{"columns":-1,"rows":-1}'                              > "$W/json_negative"
    printf '\x00\x00\x00{"columns":65535,"rows":65535}'                        > "$W/json_uint16_max"
    printf '\x00\x00\x00{"columns":65536,"rows":65536}'                        > "$W/json_uint16_overflow"
    printf '\x00\x00\x00{  "columns" : 80 , "rows" : 24  }'                   > "$W/json_extra_whitespace"
    python3 -c "import sys; sys.stdout.buffer.write(b'\x00\x00\x00' + (b'{\"a\":' * 50 + b'1' + b'}' * 50))" > "$W/json_deep_nested"
    python3 -c "
import sys
cred = b'admin'; hdr = b'\x01' + len(cred).to_bytes(2,'big') + cred
sys.stdout.buffer.write(hdr + b'{\"columns\":80,\"rows\":24,\"AuthToken\":\"' + b'A'*5000 + b'\"}')
" > "$W/json_huge_token"
    python3 -c "import sys; cred=b'admin'; h=b'\x01'+len(cred).to_bytes(2,'big')+cred; sys.stdout.buffer.write(h+b'{\"columns\":80,\"rows\":24,\"AuthToken\":true}')"    > "$W/auth_token_bool"
    python3 -c "import sys; cred=b'admin'; h=b'\x01'+len(cred).to_bytes(2,'big')+cred; sys.stdout.buffer.write(h+b'{\"columns\":80,\"rows\":24,\"AuthToken\":null}')"    > "$W/auth_token_null"
    python3 -c "import sys; cred=b'admin'; h=b'\x01'+len(cred).to_bytes(2,'big')+cred; sys.stdout.buffer.write(h+b'{\"columns\":80,\"rows\":24,\"AuthToken\":12345}')"   > "$W/auth_token_int"
    python3 -c "import sys; cred=b'admin'; h=b'\x01'+len(cred).to_bytes(2,'big')+cred; sys.stdout.buffer.write(h+b'{\"AuthToken\":\"wrong\",\"AuthToken\":\"admin\"}')" > "$W/auth_token_dup"
    python3 -c "
import sys
cred = b'A'*200
sys.stdout.buffer.write(b'\x01' + len(cred).to_bytes(2,'big') + cred + b'{\"AuthToken\":\"' + cred + b'\"}')
" > "$W/auth_long_cred"
    echo "[+] Generated $(ls "$W" | wc -l) seeds for websocket_auth"

    # ── http_parsing ─────────────────────────────────────────────────────────
    echo "[*] Generating corpus/http_parsing/"
    local H="$SCRIPT_DIR/corpus/http_parsing"

    printf 'GET / HTTP/1.1\r\nHost: localhost:7681\r\n\r\n'                                                                    > "$H/get_root"
    printf 'GET /token HTTP/1.1\r\nHost: localhost:7681\r\nAuthorization: Basic YWRtaW46cGFzcw==\r\n\r\n'                      > "$H/get_with_auth"
    printf 'GET /ws HTTP/1.1\r\nHost: localhost:7681\r\nOrigin: http://localhost:7681\r\n\r\n'                                  > "$H/get_with_origin"
    printf 'GET / HTTP/1.1\r\nHost: localhost:7681\r\nAuthorization: Basic YWRtaW46cGFzcw==\r\nOrigin: http://localhost:7681\r\n\r\n' > "$H/get_full_headers"
    printf 'GET /../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n'                                                      > "$H/path_traversal"
    printf 'GET //etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n'                                                              > "$H/path_double_slash"
    printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic \r\n\r\n'                                                > "$H/auth_empty_b64"
    printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer token123\r\n\r\n'                                       > "$H/auth_bearer"
    printf 'GET / HTTP/1.1\r\nHost: localhost:7681\r\nOrigin: http://evil.com\r\n\r\n'                                        > "$H/csrf_mismatch"
    printf 'GET / HTTP/1.1\r\nHost: target.com\r\nOrigin: http://target.com.evil.com\r\n\r\n'                                 > "$H/csrf_subdomain_trick"
    printf 'GARBAGE\r\n\r\n'                                                                                                    > "$H/malformed_no_space"
    printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic user:password\r\n\r\n'                                   > "$H/auth_with_colon"
    printf 'GET /ws HTTP/1.1\r\nHost: localhost:7681\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' > "$H/ws_upgrade"
    printf 'GET /%%s%%s%%s%%n HTTP/1.1\r\nHost: %%x%%x%%x\r\nAuthorization: Basic %%n%%n\r\n\r\n'                              > "$H/fmt_everywhere"
    python3 -c "
import sys
path = '/' + 'A' * 200
sys.stdout.buffer.write(f'GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
" > "$H/path_long_200"
    python3 -c "
import sys
auth = 'Basic ' + 'A' * 300
sys.stdout.buffer.write(f'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: {auth}\r\n\r\n'.encode())
" > "$H/auth_long_value"
    python3 -c "
import sys
req = 'GET / HTTP/1.1\r\n'
for i in range(100): req += f'X-Header-{i}: value-{i}\r\n'
req += '\r\n'
sys.stdout.buffer.write(req.encode())
" > "$H/many_headers"
    echo "[+] Generated $(ls "$H" | wc -l) seeds for http_parsing"

    echo "[+] Total corpus: $(find "$SCRIPT_DIR/corpus" -type f | wc -l) files"
}

# ─── 5. crash backup crontab ──────────────────────────────────────────────────

setup_crash_backup() {
    local BACKUP_DIR="$SCRIPT_DIR/crashes-backup"

    # Write the backup script
    cat > "$BACKUP_SCRIPT" <<BKUP
#!/bin/bash
# Auto-generated by build_fuzzers.sh — backs up AFL++ crashes to a dated archive
# $CRONTAB_MARKER
SCRIPT_DIR="$SCRIPT_DIR"
BACKUP_DIR="$BACKUP_DIR"
OUTPUT_DIR="\$SCRIPT_DIR/output"

mkdir -p "\$BACKUP_DIR"

HAS_CRASHES=false
for crash_dir in "\$OUTPUT_DIR"/*/main/crashes "\$OUTPUT_DIR"/*/cmplog/crashes; do
    [ -d "\$crash_dir" ] || continue
    count=\$(find "\$crash_dir" -maxdepth 1 -name 'id:*' 2>/dev/null | wc -l)
    [ "\$count" -gt 0 ] || continue
    HAS_CRASHES=true
    break
done

\$HAS_CRASHES || exit 0

STAMP=\$(date +%Y%m%d_%H%M%S)
ARCHIVE="\$BACKUP_DIR/crashes_\${STAMP}.tar.gz"
tar -czf "\$ARCHIVE" \
    --exclude='README.txt' \
    \$(find "\$OUTPUT_DIR" -type d -name 'crashes' 2>/dev/null | tr '\n' ' ') \
    2>/dev/null || true

echo "[\$(date)] Backed up crashes → \$ARCHIVE" >> "\$BACKUP_DIR/backup.log"
BKUP
    chmod +x "$BACKUP_SCRIPT"
    echo "[+] Created $BACKUP_SCRIPT"

    # Install crontab entry (idempotent — remove stale entry first)
    local TMPFILE
    TMPFILE=$(mktemp)
    crontab -l 2>/dev/null | grep -v "$CRONTAB_MARKER" | grep -v "backup_crashes.sh" > "$TMPFILE" || true
    {
        cat "$TMPFILE"
        echo "$CRONTAB_MARKER"
        echo "*/15 * * * * $BACKUP_SCRIPT >> $SCRIPT_DIR/crashes-backup/backup.log 2>&1"
    } | crontab -
    rm -f "$TMPFILE"
    echo "[+] Crontab entry installed (every 15 min)"
    crontab -l | grep -A1 "$CRONTAB_MARKER"
}

# ─── 6. select compiler ───────────────────────────────────────────────────────

case "$MODE" in
    afl)
        if ! command -v afl-clang-fast &>/dev/null; then
            echo "[!] afl-clang-fast not found. Install AFL++ first."
            exit 1
        fi
        CC="afl-clang-fast"
        CFLAGS="-fsanitize=$SANITIZER -g -O1"
        SUFFIX=""
        ;;
    libfuzzer)
        if ! command -v clang &>/dev/null; then
            echo "[!] clang not found. Install clang first."
            exit 1
        fi
        CC="clang"
        CFLAGS="-fsanitize=fuzzer,$SANITIZER -g -O1"
        SUFFIX="_lf"
        ;;
    *)
        echo "[!] Unknown mode: $MODE  (use 'afl' or 'libfuzzer')"
        exit 1
        ;;
esac

# ─── find json-c ─────────────────────────────────────────────────────────────

JSON_C_CFLAGS=$(pkg-config --cflags json-c 2>/dev/null || echo "")
JSON_C_LIBS=$(pkg-config --libs   json-c 2>/dev/null || echo "-ljson-c")
if [ -z "$JSON_C_CFLAGS" ]; then
    for d in /usr/include /usr/local/include; do
        [ -f "$d/json-c/json.h" ] && JSON_C_CFLAGS="-I$d" && break
    done
fi
if [ -z "$JSON_C_CFLAGS" ]; then
    echo "[!] json-c headers not found. Run: sudo apt-get install libjson-c-dev"
    exit 1
fi

# ─── run setup stages ────────────────────────────────────────────────────────

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/7] Installing dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
install_deps

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2/7] Setting up ttyd source + instrumented objects"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
setup_ttyd_source

# ─── build harnesses ─────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/7] Building harnesses (with real ttyd code)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Common flags for all harnesses: our mock includes take priority over system
COMMON_CFLAGS="$CFLAGS -I$FUZZ_INCLUDE -I$TTYD_SRC/src $JSON_C_CFLAGS"
COMMON_CFLAGS="$COMMON_CFLAGS -Wno-implicit-function-declaration -Wno-int-conversion"

# http.c and protocol.c are compiled into each harness via #include — do NOT
# include their pre-compiled objects here or every symbol will be defined twice.
MOCK_OBJS="$TTYD_OBJ/utils.o"
MOCK_OBJS="$MOCK_OBJS $TTYD_OBJ/fuzz_lws_mock.o $TTYD_OBJ/mock_server_globals.o $TTYD_OBJ/mock_pty_stubs.o"

# http.c decompresses gzip-encoded HTML using zlib
EXTRA_LIBS="-lz"

echo "[*] Building fuzz_auth_header..."
$CC $COMMON_CFLAGS fuzz_auth_header.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS -o fuzz_auth_header$SUFFIX
echo "[+] Built: fuzz_auth_header$SUFFIX"

echo "[*] Building fuzz_websocket_auth..."
$CC $COMMON_CFLAGS fuzz_websocket_auth.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS -o fuzz_websocket_auth$SUFFIX
echo "[+] Built: fuzz_websocket_auth$SUFFIX"

echo "[*] Building fuzz_http_parsing..."
$CC $COMMON_CFLAGS fuzz_http_parsing.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS -o fuzz_http_parsing$SUFFIX
echo "[+] Built: fuzz_http_parsing$SUFFIX"

# CmpLog variants (AFL++ only)
if [ "$MODE" = "afl" ]; then
    echo
    echo "[*] Building CmpLog variants..."
    for target in fuzz_auth_header fuzz_websocket_auth; do
        AFL_LLVM_CMPLOG=1 $CC $COMMON_CFLAGS ${target}.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS \
            -o ${target}_cmplog
        echo "[+] Built: ${target}_cmplog"
    done
    AFL_LLVM_CMPLOG=1 $CC $COMMON_CFLAGS fuzz_http_parsing.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS \
        -o fuzz_http_parsing_cmplog
    echo "[+] Built: fuzz_http_parsing_cmplog"
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[4/7] Setting up dictionaries"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
setup_dictionaries

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[5/7] Generating seed corpus"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
generate_corpus

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[6/7] Installing crash-backup crontab"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
setup_crash_backup

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[7/7] Done"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "Ready to fuzz:"
if [ "$MODE" = "afl" ]; then
    echo "  ./run-fuzzers.sh          # launch all targets in tmux"
    echo "  afl-fuzz -i corpus/auth_header -o output/auth_header -x dictionaries/http.dict ./fuzz_auth_header"
else
    echo "  ./fuzz_auth_header_lf corpus/auth_header/"
fi
echo
echo "Crashes backed up automatically every 15 min → crashes-backup/"
echo "To stop backup: ./clean.sh"
