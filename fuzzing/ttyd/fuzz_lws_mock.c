/* Mock implementations of libwebsockets runtime functions for fuzzing ttyd.
 * lws_hdr_copy / lws_hdr_custom_* return fuzzer-controlled data so AFL++
 * can drive the auth logic.  All other lws functions are safe no-ops.      */

#include "fuzz-include/libwebsockets.h"
#include "fuzz_lws_mock.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* ── fuzzer-controlled state ─────────────────────────────────────────── */
char _fuzz_auth_header[4096];
int  _fuzz_auth_header_len;
char _fuzz_custom_header[4096];
int  _fuzz_custom_header_len;
char _fuzz_uri_path[4096];
int  _fuzz_uri_path_len;
char _fuzz_origin[4096];
int  _fuzz_origin_len;
char _fuzz_host[4096];
int  _fuzz_host_len;

char _fuzz_uri_args[FUZZ_MAX_URI_ARGS][256];
int  _fuzz_uri_args_len[FUZZ_MAX_URI_ARGS];
int  _fuzz_uri_args_count;

int    _fuzz_is_final_fragment = 1;
size_t _fuzz_remaining_payload = 0;

void fuzz_lws_reset(void) {
    memset(_fuzz_auth_header,   0, sizeof(_fuzz_auth_header));
    _fuzz_auth_header_len   = 0;
    memset(_fuzz_custom_header, 0, sizeof(_fuzz_custom_header));
    _fuzz_custom_header_len = 0;
    memset(_fuzz_uri_path, 0, sizeof(_fuzz_uri_path));
    _fuzz_uri_path_len = 0;
    memset(_fuzz_origin, 0, sizeof(_fuzz_origin));
    _fuzz_origin_len = 0;
    memset(_fuzz_host, 0, sizeof(_fuzz_host));
    _fuzz_host_len = 0;
    memset(_fuzz_uri_args, 0, sizeof(_fuzz_uri_args));
    memset(_fuzz_uri_args_len, 0, sizeof(_fuzz_uri_args_len));
    _fuzz_uri_args_count = 0;
    _fuzz_is_final_fragment = 1;
    _fuzz_remaining_payload = 0;
}

/* ── header accessors ────────────────────────────────────────────────── */

/* Helper: copy from a source buffer into dest, return bytes copied */
static int copy_hdr(char *dest, int len, const char *src, int srclen) {
    if (!dest || len <= 0) return 0;
    if (!src || srclen <= 0) { dest[0] = '\0'; return 0; }
    int n = srclen < len - 1 ? srclen : len - 1;
    memcpy(dest, src, n);
    dest[n] = '\0';
    return n;
}

int lws_hdr_copy(struct lws *wsi, char *dest, int len,
                 enum lws_token_indexes h) {
    switch (h) {
    case WSI_TOKEN_HTTP_AUTHORIZATION:
        return copy_hdr(dest, len, _fuzz_auth_header, _fuzz_auth_header_len);
    case WSI_TOKEN_GET_URI:
    case WSI_TOKEN_HTTP_COLON_PATH:
        return copy_hdr(dest, len, _fuzz_uri_path, _fuzz_uri_path_len);
    case WSI_TOKEN_ORIGIN:
        return copy_hdr(dest, len, _fuzz_origin, _fuzz_origin_len);
    case WSI_TOKEN_HOST:
        return copy_hdr(dest, len, _fuzz_host, _fuzz_host_len);
    default:
        if (dest && len > 0) dest[0] = '\0';
        return 0;
    }
}

int lws_hdr_custom_length(struct lws *wsi, const char *name, int nlen) {
    return _fuzz_custom_header_len;
}

int lws_hdr_custom_copy(struct lws *wsi, char *dst, int len,
                         const char *name, int nlen) {
    return copy_hdr(dst, len, _fuzz_custom_header, _fuzz_custom_header_len);
}

int lws_hdr_copy_fragment(struct lws *wsi, char *dst, int len,
                           enum lws_token_indexes h, int frag_idx) {
    if (h == WSI_TOKEN_HTTP_URI_ARGS &&
        frag_idx < _fuzz_uri_args_count && frag_idx < FUZZ_MAX_URI_ARGS) {
        return copy_hdr(dst, len,
                        _fuzz_uri_args[frag_idx],
                        _fuzz_uri_args_len[frag_idx]);
    }
    if (dst && len > 0) dst[0] = '\0';
    return 0;
}

/* ── URI parsing ─────────────────────────────────────────────────────── */
/* Simple parser that extracts protocol, host, port, path from a URI.
 * Modifies the input string in-place (like the real lws_parse_uri).     */
int lws_parse_uri(char *p, const char **prot, const char **host,
                  int *port, const char **path) {
    if (!p || !*p) {
        if (prot)  *prot  = "";
        if (host)  *host  = "";
        if (port)  *port  = 0;
        if (path)  *path  = "";
        return -1;
    }

    /* Find protocol: "http://" or "https://" etc. */
    char *sep = strstr(p, "://");
    if (sep) {
        *sep = '\0';
        if (prot) *prot = p;
        p = sep + 3;
    } else {
        if (prot) *prot = "";
    }

    /* host[:port][/path] */
    if (host) *host = p;

    /* Find path separator */
    char *slash = strchr(p, '/');
    if (slash) {
        if (path) *path = slash + 1;
        *slash = '\0';
    } else {
        if (path) *path = "";
    }

    /* Find port in host part */
    char *colon = strchr(p, ':');
    if (colon) {
        *colon = '\0';
        if (port) *port = atoi(colon + 1);
    } else {
        if (port) *port = 0;
    }

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
int lws_is_final_fragment(struct lws *wsi) { return _fuzz_is_final_fragment; }
size_t lws_remaining_packet_payload(struct lws *wsi) { return _fuzz_remaining_payload; }
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
