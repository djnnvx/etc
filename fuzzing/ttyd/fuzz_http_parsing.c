/*
 * AFL++ / LibFuzzer Harness for TTYD HTTP Request Parsing
 *
 * Target: HTTP header parsing, path validation, credential extraction
 * Goal: Find parsing bugs, buffer overflows, injection vulnerabilities
 *
 * Compile with AFL++:
 *   afl-clang-fast -fsanitize=address -g -O1 fuzz_http_parsing.c -o fuzz_http_parsing
 *
 * Compile with libFuzzer:
 *   clang -fsanitize=fuzzer,address -g -O1 fuzz_http_parsing.c -o fuzz_http_parsing
 *
 * Run:
 *   afl-fuzz -i input/ -o output/ ./fuzz_http_parsing
 *   ./fuzz_http_parsing  # libFuzzer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>

#define MAX_PATH_LEN 128
#define MAX_HEADER_LEN 256

// Simulated HTTP parsing
typedef struct {
    char path[MAX_PATH_LEN];
    char auth_header[MAX_HEADER_LEN];
    char origin_header[MAX_HEADER_LEN];
    char host_header[MAX_HEADER_LEN];
} http_request_t;

// Parse HTTP request from fuzzer input
bool parse_http_request(const uint8_t *data, size_t size, http_request_t *req) {
    if (size == 0 || data == NULL || req == NULL) return false;

    memset(req, 0, sizeof(http_request_t));

    // Simple HTTP request parsing
    // Format: METHOD PATH\r\nHeader: Value\r\n\r\n

    const char *ptr = (const char *)data;
    const char *end = ptr + size;

    // Parse request line
    const char *path_start = strchr(ptr, ' ');
    if (!path_start || path_start >= end) return false;
    path_start++;

    const char *path_end = strchr(path_start, ' ');
    if (!path_end || path_end >= end) path_end = strchr(path_start, '\r');
    if (!path_end || path_end >= end) path_end = end;

    size_t path_len = path_end - path_start;
    if (path_len >= MAX_PATH_LEN) path_len = MAX_PATH_LEN - 1;
    memcpy(req->path, path_start, path_len);
    req->path[path_len] = '\0';

    // Parse headers
    ptr = path_end;
    while (ptr < end) {
        // Find header line
        const char *line_start = strchr(ptr, '\n');
        if (!line_start || line_start >= end) break;
        line_start++;

        if (line_start[0] == '\r' || line_start[0] == '\n') break;  // End of headers

        const char *colon = strchr(line_start, ':');
        if (!colon || colon >= end) {
            ptr = line_start;
            continue;
        }

        // Extract header name and value
        size_t name_len = colon - line_start;
        const char *value_start = colon + 1;
        while (value_start < end && isspace(*value_start)) value_start++;

        const char *value_end = strchr(value_start, '\r');
        if (!value_end || value_end >= end) value_end = end;

        size_t value_len = value_end - value_start;

        // Check for specific headers
        if (name_len == 13 && strncasecmp(line_start, "Authorization", 13) == 0) {
            if (value_len >= MAX_HEADER_LEN) value_len = MAX_HEADER_LEN - 1;
            memcpy(req->auth_header, value_start, value_len);
            req->auth_header[value_len] = '\0';
        } else if (name_len == 6 && strncasecmp(line_start, "Origin", 6) == 0) {
            if (value_len >= MAX_HEADER_LEN) value_len = MAX_HEADER_LEN - 1;
            memcpy(req->origin_header, value_start, value_len);
            req->origin_header[value_len] = '\0';
        } else if (name_len == 4 && strncasecmp(line_start, "Host", 4) == 0) {
            if (value_len >= MAX_HEADER_LEN) value_len = MAX_HEADER_LEN - 1;
            memcpy(req->host_header, value_start, value_len);
            req->host_header[value_len] = '\0';
        }

        ptr = value_end;
    }

    return true;
}

// Validate path (check for path traversal, etc.)
bool validate_path(const char *path) {
    if (path == NULL || path[0] == '\0') return false;

    // Check for path traversal sequences
    if (strstr(path, "..") != NULL) return false;
    if (strstr(path, "//") != NULL) return false;

    // Check for null bytes
    size_t len = strlen(path);
    for (size_t i = 0; i < len; i++) {
        if (path[i] == '\0') return false;
    }

    return true;
}

// Check origin vs host (CSRF protection)
bool check_origin(const char *origin, const char *host) {
    if (origin == NULL || host == NULL) return false;
    if (origin[0] == '\0' || host[0] == '\0') return false;

    // Extract hostname from origin (http://host:port)
    const char *host_start = strstr(origin, "://");
    if (host_start) host_start += 3;
    else host_start = origin;

    // Compare with Host header
    return strncasecmp(host_start, host, strlen(host)) == 0;
}

// Extract and validate Basic auth
bool extract_basic_auth(const char *auth_header, char *username, char *password, size_t max_len) {
    if (auth_header == NULL || username == NULL || password == NULL) return false;

    // Check for "Basic " prefix
    if (strncmp(auth_header, "Basic ", 6) != 0) return false;

    const char *encoded = auth_header + 6;

    // Simple base64 decode (not production quality)
    // For fuzzing purposes, just extract the string
    size_t len = strlen(encoded);
    if (len >= max_len) len = max_len - 1;

    // Look for colon separator in decoded value (simplified)
    const char *colon = strchr(encoded, ':');
    if (colon) {
        size_t user_len = colon - encoded;
        if (user_len >= max_len) user_len = max_len - 1;
        memcpy(username, encoded, user_len);
        username[user_len] = '\0';

        size_t pass_len = len - user_len - 1;
        if (pass_len >= max_len) pass_len = max_len - 1;
        memcpy(password, colon + 1, pass_len);
        password[pass_len] = '\0';
    }

    return true;
}

// Fuzzing target
int fuzz_target(const uint8_t *data, size_t size) {
    if (size < 10) return 0;

    http_request_t req;
    if (!parse_http_request(data, size, &req)) {
        return 0;
    }

    // Validate parsed data
    bool path_valid = validate_path(req.path);
    bool origin_valid = check_origin(req.origin_header, req.host_header);

    char username[128] = {0};
    char password[128] = {0};
    bool auth_valid = extract_basic_auth(req.auth_header, username, password, sizeof(username));

    // Exercise various code paths
    if (path_valid && origin_valid && auth_valid) {
        // All validations passed
    }

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
