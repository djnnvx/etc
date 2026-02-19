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

/* Additional header mocks for websocket/protocol fuzzing */
extern char _fuzz_uri_path[4096];
extern int  _fuzz_uri_path_len;
extern char _fuzz_origin[4096];
extern int  _fuzz_origin_len;
extern char _fuzz_host[4096];
extern int  _fuzz_host_len;

/* URI arg fragments for lws_hdr_copy_fragment(WSI_TOKEN_HTTP_URI_ARGS) */
#define FUZZ_MAX_URI_ARGS 8
extern char _fuzz_uri_args[FUZZ_MAX_URI_ARGS][256];
extern int  _fuzz_uri_args_len[FUZZ_MAX_URI_ARGS];
extern int  _fuzz_uri_args_count;

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
static inline void fuzz_lws_set_uri_path(const char *v, int len) {
    int n = len < 4095 ? len : 4095;
    memcpy(_fuzz_uri_path, v, n);
    _fuzz_uri_path[n] = '\0';
    _fuzz_uri_path_len = n;
}
static inline void fuzz_lws_set_origin(const char *v, int len) {
    int n = len < 4095 ? len : 4095;
    memcpy(_fuzz_origin, v, n);
    _fuzz_origin[n] = '\0';
    _fuzz_origin_len = n;
}
static inline void fuzz_lws_set_host(const char *v, int len) {
    int n = len < 4095 ? len : 4095;
    memcpy(_fuzz_host, v, n);
    _fuzz_host[n] = '\0';
    _fuzz_host_len = n;
}
