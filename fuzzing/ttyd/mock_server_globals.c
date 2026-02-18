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
