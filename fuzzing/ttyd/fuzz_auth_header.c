/*
 * AFL++ / LibFuzzer Harness for TTYD Authentication Header Parsing
 *
 * Target: HTTP Authorization header parsing in check_auth()
 * Goal: Find buffer overflows, format string bugs, logic errors
 *
 * Compile with AFL++:
 *   afl-clang-fast -fsanitize=address -g -O1 fuzz_auth_header.c -o fuzz_auth_header
 *
 * Compile with libFuzzer:
 *   clang -fsanitize=fuzzer,address -g -O1 fuzz_auth_header.c -o fuzz_auth_header
 *
 * Run:
 *   afl-fuzz -i input/ -o output/ ./fuzz_auth_header
 *   ./fuzz_auth_header  # libFuzzer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

// Simulated ttyd structures
struct server_t {
    char *credential;      // Base64 encoded username:password
    char *auth_header;     // Custom auth header name
} server_instance;

struct server_t *server = &server_instance;

// Simulated check_auth logic from protocol.c
bool check_auth_fuzzing(const char *auth_header_value, const char *custom_header_value) {
    // Simulate auth_header mode
    if (server->auth_header != NULL) {
        if (custom_header_value != NULL && strlen(custom_header_value) > 0) {
            return true;
        }
        return false;
    }

    // Simulate credential mode
    if (server->credential != NULL) {
        if (auth_header_value == NULL) return false;

        char buf[256];
        size_t n = strlen(auth_header_value);
        if (n >= sizeof(buf)) n = sizeof(buf) - 1;
        memcpy(buf, auth_header_value, n);
        buf[n] = '\0';

        // Check for "Basic " prefix and compare
        if (n >= 7 && strstr(buf, "Basic ") && strcmp(buf + 6, server->credential) == 0) {
            return true;
        }
        return false;
    }

    return true;  // No auth required
}

// Base64 encoding for credential generation
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode_simple(const char *input, char *output, size_t out_size) {
    size_t len = strlen(input);
    size_t i, j = 0;

    for (i = 0; i < len && j < out_size - 1; i += 3) {
        uint32_t octet_a = i < len ? (unsigned char)input[i] : 0;
        uint32_t octet_b = i + 1 < len ? (unsigned char)input[i + 1] : 0;
        uint32_t octet_c = i + 2 < len ? (unsigned char)input[i + 2] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        if (j + 4 >= out_size) break;
        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = i + 1 < len ? base64_chars[(triple >> 6) & 0x3F] : '=';
        output[j++] = i + 2 < len ? base64_chars[triple & 0x3F] : '=';
    }
    output[j] = '\0';
}

// Fuzzing target
int fuzz_target(const uint8_t *data, size_t size) {
    if (size < 10) return 0;  // Need minimum data

    // Parse fuzzer input
    // Format: [mode:1][credential_len:2][credential][auth_header]

    uint8_t mode = data[0] % 3;  // 0=no auth, 1=basic auth, 2=custom header
    uint16_t cred_len = (data[1] << 8) | data[2];

    if (cred_len > size - 3) cred_len = size - 3;
    if (cred_len > 500) cred_len = 500;  // Reasonable limit

    char credential_raw[512] = {0};
    char credential_b64[1024] = {0};
    char auth_header_input[1024] = {0};
    char custom_header_value[256] = {0};

    // Extract credential
    if (cred_len > 0) {
        memcpy(credential_raw, data + 3, cred_len);
        credential_raw[cred_len] = '\0';
        base64_encode_simple(credential_raw, credential_b64, sizeof(credential_b64));
    }

    // Extract auth header value
    size_t remaining = size - 3 - cred_len;
    if (remaining > 0) {
        size_t copy_len = remaining < sizeof(auth_header_input) - 1 ?
                         remaining : sizeof(auth_header_input) - 1;
        memcpy(auth_header_input, data + 3 + cred_len, copy_len);
        auth_header_input[copy_len] = '\0';

        // Also extract custom header value (first 255 bytes)
        size_t custom_len = remaining < sizeof(custom_header_value) - 1 ?
                           remaining : sizeof(custom_header_value) - 1;
        memcpy(custom_header_value, data + 3 + cred_len, custom_len);
        custom_header_value[custom_len] = '\0';
    }

    // Setup server state based on mode
    if (mode == 0) {
        // No authentication required
        server->credential = NULL;
        server->auth_header = NULL;
    } else if (mode == 1) {
        // Basic auth mode
        server->credential = credential_b64[0] ? strdup(credential_b64) : NULL;
        server->auth_header = NULL;
    } else {
        // Custom header mode
        server->credential = NULL;
        server->auth_header = strdup("X-Auth-User");
    }

    // Fuzz the authentication check
    bool result = check_auth_fuzzing(auth_header_input, custom_header_value);

    // Cleanup
    if (server->credential) free(server->credential);
    if (server->auth_header) free(server->auth_header);
    server->credential = NULL;
    server->auth_header = NULL;

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
