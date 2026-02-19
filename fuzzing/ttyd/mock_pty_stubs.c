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
                           char *argv[], char *envp[])   { pty_process *p = calloc(1, sizeof(pty_process)); if (p) p->ctx = ctx; return p; }
bool       process_running(pty_process *process)         { return false; }
void       process_free(pty_process *process)            { free(process); }
int        pty_spawn(pty_process *process,
                     pty_read_cb read_cb,
                     pty_exit_cb exit_cb)                { return 0; }
void       pty_pause(pty_process *process)               {}
void       pty_resume(pty_process *process)              {}
int        pty_write(pty_process *process,
                     pty_buf_t *buf)                     { return -1; }
bool       pty_resize(pty_process *process)              { return false; }
bool       pty_kill(pty_process *process, int sig)       { return false; }
