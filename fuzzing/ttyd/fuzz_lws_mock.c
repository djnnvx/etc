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
