/*
 * AFL++ / LibFuzzer Harness for TTYD WebSocket Authentication
 *
 * Target: WebSocket AuthToken JSON parsing and validation
 * Goal: Find JSON parsing bugs, buffer overflows, logic errors
 *
 * Compile with AFL++:
 *   afl-clang-fast -fsanitize=address -g -O1 fuzz_websocket_auth.c -ljson-c -o fuzz_websocket_auth
 *
 * Compile with libFuzzer:
 *   clang -fsanitize=fuzzer,address -g -O1 fuzz_websocket_auth.c -ljson-c -o fuzz_websocket_auth
 *
 * Run:
 *   afl-fuzz -i input/ -o output/ ./fuzz_websocket_auth
 *   ./fuzz_websocket_auth  # libFuzzer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <json-c/json.h>

// Simulated ttyd structures
struct server_t {
    char *credential;
} server_instance;

struct pss_tty_t {
    bool authenticated;
} pss_instance;

struct server_t *server = &server_instance;

// Simulated parse_window_size and auth check from protocol.c
struct json_object *parse_window_size_fuzzing(const char *buf, size_t len,
                                              uint16_t *columns, uint16_t *rows) {
    if (buf == NULL || len == 0) return NULL;

    // Ensure null termination
    char *safe_buf = malloc(len + 1);
    if (!safe_buf) return NULL;
    memcpy(safe_buf, buf, len);
    safe_buf[len] = '\0';

    struct json_tokener *tok = json_tokener_new();
    struct json_object *obj = json_tokener_parse_ex(tok, safe_buf, len);
    json_tokener_free(tok);
    free(safe_buf);

    if (obj == NULL) return NULL;

    // Extract columns and rows
    struct json_object *o = NULL;
    if (json_object_object_get_ex(obj, "columns", &o)) {
        *columns = (uint16_t)json_object_get_int(o);
    }
    if (json_object_object_get_ex(obj, "rows", &o)) {
        *rows = (uint16_t)json_object_get_int(o);
    }

    return obj;
}

bool check_websocket_auth_fuzzing(const char *buf, size_t len) {
    struct pss_tty_t *pss = &pss_instance;
    pss->authenticated = false;

    uint16_t columns = 0, rows = 0;
    struct json_object *obj = parse_window_size_fuzzing(buf, len, &columns, &rows);

    if (obj == NULL) {
        return false;
    }

    if (server->credential != NULL) {
        struct json_object *o = NULL;
        if (json_object_object_get_ex(obj, "AuthToken", &o)) {
            const char *token = json_object_get_string(o);
            if (token != NULL && strcmp(token, server->credential) == 0) {
                pss->authenticated = true;
            }
        }

        if (!pss->authenticated) {
            json_object_put(obj);
            return false;
        }
    }

    json_object_put(obj);
    return true;
}

// Fuzzing target
int fuzz_target(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    // Parse fuzzer input
    // Format: [has_credential:1][credential_len:1][credential][json_message]

    bool has_credential = (data[0] % 2) == 1;
    uint8_t cred_len = data[1];

    if (cred_len > size - 2) cred_len = size - 2;
    if (cred_len > 200) cred_len = 200;

    char credential[256] = {0};
    if (has_credential && cred_len > 0) {
        memcpy(credential, data + 2, cred_len);
        credential[cred_len] = '\0';
        server->credential = credential;
    } else {
        server->credential = NULL;
    }

    // Extract JSON message
    size_t json_start = 2 + (has_credential ? cred_len : 0);
    if (json_start >= size) {
        server->credential = NULL;
        return 0;
    }

    size_t json_len = size - json_start;
    const char *json_data = (const char *)(data + json_start);

    // Fuzz the WebSocket auth check
    bool result = check_websocket_auth_fuzzing(json_data, json_len);

    server->credential = NULL;
    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
// AFL++ persistent mode
__AFL_FUZZ_INIT();

int main(void) {
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_target(buf, len);
    }

    return 0;
}
#else
// LibFuzzer mode
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return fuzz_target(data, size);
}

// Standalone mode for testing
#ifndef LIBFUZZER
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    fuzz_target(data, size);
    free(data);

    printf("Test completed successfully\n");
    return 0;
}
#endif
#endif
