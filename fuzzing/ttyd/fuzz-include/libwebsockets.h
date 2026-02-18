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
