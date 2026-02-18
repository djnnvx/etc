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
