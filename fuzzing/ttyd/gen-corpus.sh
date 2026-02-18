#!/bin/bash
# Generate seed corpus for TTYD fuzzing harnesses
# Creates structured inputs matching each harness's expected format

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$SCRIPT_DIR/corpus/auth_header"
mkdir -p "$SCRIPT_DIR/corpus/websocket_auth"
mkdir -p "$SCRIPT_DIR/corpus/http_parsing"

echo "[*] Generating corpus for fuzz_auth_header"
echo "    Format: [mode:1][credential_len:2][credential][auth_header_value]"

DIR="$SCRIPT_DIR/corpus/auth_header"

# Mode 0: no auth required
# mode=0x00, cred_len=0x0000, payload
printf '\x00\x00\x00anything-goes' > "$DIR/noauth_basic"
printf '\x00\x00\x00' > "$DIR/noauth_empty"
printf '\x00\x00\x00Basic YWRtaW46cGFzcw==' > "$DIR/noauth_with_basic"

# Mode 1: basic auth (mode % 3 == 1)
# mode=0x01, cred_len=0x000b (11), credential="admin:pass", auth_header
printf '\x01\x00\x0badmin:pass\x00Basic YWRtaW46cGFzcw==' > "$DIR/basic_valid"
printf '\x01\x00\x0badmin:pass\x00Basic INVALIDBASE64==' > "$DIR/basic_mismatch"
printf '\x01\x00\x0badmin:pass\x00Basic ' > "$DIR/basic_empty_token"
printf '\x01\x00\x0badmin:pass\x00' > "$DIR/basic_no_header"
printf '\x01\x00\x0badmin:pass\x00Bearer token123' > "$DIR/basic_wrong_scheme"
printf '\x01\x00\x0badmin:pass\x00basic YWRtaW46cGFzcw==' > "$DIR/basic_lowercase"
printf '\x01\x00\x00\x00Basic YWRtaW46cGFzcw==' > "$DIR/basic_no_credential"

# Mode 1: long credentials
python3 -c "
import sys
cred = b'A' * 255 + b':' + b'B' * 255
cred_len = len(cred)
header = b'\x01' + cred_len.to_bytes(2, 'big') + cred + b'Basic ' + b'A' * 500
sys.stdout.buffer.write(header)
" > "$DIR/basic_long_cred"

# Mode 1: special characters in credentials
printf '\x01\x00\x13user:p@ss\x00w0rd!#$%%\x00Basic dXNlcjpwQHNzAHcwcmQhIyQl' > "$DIR/basic_special_chars"
printf '\x01\x00\x0auser\x00:pass\x00Basic dXNlcgA6cGFzcw==' > "$DIR/basic_null_in_cred"

# Mode 2: custom header auth (mode % 3 == 2)
printf '\x02\x00\x00some-token-value' > "$DIR/custom_with_value"
printf '\x02\x00\x00' > "$DIR/custom_empty"
printf '\x02\x00\x00\x00' > "$DIR/custom_null_byte"

# Edge cases
printf '\x01\x00\x01\x00\x00' > "$DIR/edge_single_byte_cred"
printf '\x01\xff\xff' > "$DIR/edge_huge_cred_len"

# Format string attempts
printf '\x01\x00\x10%%s%%s%%s%%s%%s%%s%%s%%s\x00Basic %%x%%x%%x%%x' > "$DIR/fmt_string"
printf '\x01\x00\x04%%n%%n\x00%%n%%n%%n%%n' > "$DIR/fmt_write"

# Buffer boundary sizes
python3 -c "
import sys
# 254 byte auth header (near buf[256] boundary)
cred = b'x:y'
header = b'Basic ' + b'A' * 248
sys.stdout.buffer.write(b'\x01\x00\x03' + cred + header)
" > "$DIR/boundary_254"

python3 -c "
import sys
# 256 byte auth header (exact buf[256] boundary)
cred = b'x:y'
header = b'Basic ' + b'A' * 250
sys.stdout.buffer.write(b'\x01\x00\x03' + cred + header)
" > "$DIR/boundary_256"

python3 -c "
import sys
# 257 byte auth header (overflow buf[256])
cred = b'x:y'
header = b'Basic ' + b'A' * 251
sys.stdout.buffer.write(b'\x01\x00\x03' + cred + header)
" > "$DIR/boundary_257"

# Mixed-case Basic prefix variations
printf '\x01\x00\x0badmin:pass\x00BASIC YWRtaW46cGFzcw==' > "$DIR/basic_uppercase"
printf '\x01\x00\x0badmin:pass\x00bAsIc YWRtaW46cGFzcw==' > "$DIR/basic_mixedcase"

# Base64 padding edge cases
printf '\x01\x00\x02a:\x00Basic YTo=' > "$DIR/basic_b64_pad1"
printf '\x01\x00\x01a\x00Basic YQ==' > "$DIR/basic_b64_pad2"
printf '\x01\x00\x03abc\x00Basic YWJj' > "$DIR/basic_b64_nopad"
printf '\x01\x00\x05ad:mn\x00Basic =====' > "$DIR/basic_b64_allpad"
printf '\x01\x00\x05ad:mn\x00Basic @#$!!' > "$DIR/basic_b64_invalid_chars"

# Credential separator positions
printf '\x01\x00\x01:\x00Basic Og==' > "$DIR/basic_colon_only"
printf '\x01\x00\x07:::::::' > "$DIR/basic_all_colons"
printf '\x01\x00\x0aadmin:a:b:c\x00Basic YWRtaW46YTpiOmM=' > "$DIR/basic_multi_colon"

# Whitespace in auth header
printf '\x01\x00\x0badmin:pass\x00Basic  YWRtaW46cGFzcw==' > "$DIR/basic_double_space"
printf '\x01\x00\x0badmin:pass\x00 Basic YWRtaW46cGFzcw==' > "$DIR/basic_leading_space"

echo "[+] Generated $(ls "$DIR" | wc -l) seeds for auth_header"

###############################################################################
echo
echo "[*] Generating corpus for fuzz_websocket_auth"
echo "    Format: [has_credential:1][credential_len:1][credential][json_message]"

DIR="$SCRIPT_DIR/corpus/websocket_auth"

# No credential (even byte = no cred)
printf '\x00\x00{"columns":80,"rows":24}' > "$DIR/noauth_normal"
printf '\x00\x00{"columns":200,"rows":50}' > "$DIR/noauth_large_term"
printf '\x00\x00{}' > "$DIR/noauth_empty_json"
printf '\x00\x00{"columns":80,"rows":24,"AuthToken":"ignored"}' > "$DIR/noauth_with_token"

# With credential (odd byte = has cred)
printf '\x01\x05admin{"columns":80,"rows":24,"AuthToken":"admin"}' > "$DIR/auth_valid"
printf '\x01\x05admin{"columns":80,"rows":24,"AuthToken":"wrong"}' > "$DIR/auth_invalid"
printf '\x01\x05admin{"columns":80,"rows":24}' > "$DIR/auth_missing_token"
printf '\x01\x05admin{"AuthToken":"admin"}' > "$DIR/auth_no_dimensions"
printf '\x01\x00{"columns":80,"rows":24}' > "$DIR/auth_empty_cred"

# Malformed JSON
printf '\x00\x00{invalid json}' > "$DIR/json_malformed"
printf '\x00\x00{"columns":' > "$DIR/json_truncated"
printf '\x00\x00' > "$DIR/json_empty"
printf '\x00\x00\x00' > "$DIR/json_null"
printf '\x01\x03foo[1,2,3]' > "$DIR/json_array"
printf '\x01\x03foo"just a string"' > "$DIR/json_string"

# Large/extreme values
printf '\x00\x00{"columns":99999,"rows":99999}' > "$DIR/json_huge_values"
printf '\x00\x00{"columns":-1,"rows":-1}' > "$DIR/json_negative"
printf '\x00\x00{"columns":0,"rows":0}' > "$DIR/json_zero"
printf '\x00\x00{"columns":65535,"rows":65535}' > "$DIR/json_uint16_max"
printf '\x00\x00{"columns":65536,"rows":65536}' > "$DIR/json_uint16_overflow"

# Deeply nested / large JSON
python3 -c "
import sys
nested = '{\"a\":' * 50 + '1' + '}' * 50
sys.stdout.buffer.write(b'\x00\x00' + nested.encode())
" > "$DIR/json_deep_nested"

python3 -c "
import sys
big = '{\"columns\":80,\"rows\":24,\"AuthToken\":\"' + 'A' * 5000 + '\"}'
sys.stdout.buffer.write(b'\x01\x05admin' + big.encode())
" > "$DIR/json_huge_token"

# Unicode / special strings in JSON
printf '\x01\x05admin{"columns":80,"rows":24,"AuthToken":"\x00\x00\x00"}' > "$DIR/json_null_bytes_token"
printf '\x00\x00{"columns":80,"rows":24,"extra":"\\u0000\\u0000"}' > "$DIR/json_unicode_null"

# Format strings in JSON
printf '\x01\x05admin{"AuthToken":"%%s%%s%%s%%s%%n"}' > "$DIR/json_fmt_string"

# AuthToken type confusion (non-string values)
printf '\x01\x05admin{"columns":80,"rows":24,"AuthToken":true}' > "$DIR/auth_token_bool"
printf '\x01\x05admin{"columns":80,"rows":24,"AuthToken":null}' > "$DIR/auth_token_null"
printf '\x01\x05admin{"columns":80,"rows":24,"AuthToken":12345}' > "$DIR/auth_token_int"
printf '\x01\x05admin{"columns":80,"rows":24,"AuthToken":["admin"]}' > "$DIR/auth_token_array"
printf '\x01\x05admin{"columns":80,"rows":24,"AuthToken":{"nested":"admin"}}' > "$DIR/auth_token_object"

# Duplicate keys
printf '\x01\x05admin{"AuthToken":"wrong","AuthToken":"admin"}' > "$DIR/auth_token_dup"
printf '\x00\x00{"columns":80,"columns":200,"rows":24}' > "$DIR/json_dup_columns"

# Very long key names
python3 -c "
import sys
key = 'A' * 1000
msg = '{\"' + key + '\":1,\"columns\":80,\"rows\":24}'
sys.stdout.buffer.write(b'\x00\x00' + msg.encode())
" > "$DIR/json_long_key"

# Whitespace variations in JSON
printf '\x00\x00{  "columns" : 80 , "rows" : 24  }' > "$DIR/json_extra_whitespace"
printf '\x00\x00{"columns":80,"rows":24}\x00garbage' > "$DIR/json_trailing_garbage"

# Large credential
python3 -c "
import sys
cred = b'A' * 200
sys.stdout.buffer.write(b'\x01\xc8' + cred + b'{\"AuthToken\":\"' + cred + b'\"}')
" > "$DIR/auth_long_cred"

echo "[+] Generated $(ls "$DIR" | wc -l) seeds for websocket_auth"

###############################################################################
echo
echo "[*] Generating corpus for fuzz_http_parsing"
echo "    Format: raw HTTP request"

DIR="$SCRIPT_DIR/corpus/http_parsing"

# Standard valid requests
printf 'GET / HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/get_root"
printf 'GET /token HTTP/1.1\r\nHost: localhost:7681\r\nAuthorization: Basic YWRtaW46cGFzcw==\r\n\r\n' > "$DIR/get_with_auth"
printf 'GET /ws HTTP/1.1\r\nHost: localhost:7681\r\nOrigin: http://localhost:7681\r\n\r\n' > "$DIR/get_with_origin"
printf 'GET / HTTP/1.1\r\nHost: localhost:7681\r\nAuthorization: Basic YWRtaW46cGFzcw==\r\nOrigin: http://localhost:7681\r\n\r\n' > "$DIR/get_full_headers"
printf 'POST /token HTTP/1.1\r\nHost: localhost:7681\r\nContent-Length: 0\r\n\r\n' > "$DIR/post_token"

# Path traversal attempts
printf 'GET /../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n' > "$DIR/path_traversal_basic"
printf 'GET /..%%2f..%%2f..%%2fetc%%2fpasswd HTTP/1.1\r\nHost: localhost\r\n\r\n' > "$DIR/path_traversal_encoded"
printf 'GET /%%2e%%2e/%%2e%%2e/etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n' > "$DIR/path_traversal_dot_encoded"
printf 'GET //etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n' > "$DIR/path_double_slash"
printf 'GET /./././../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n' > "$DIR/path_traversal_mixed"
printf 'GET /\x00/etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n' > "$DIR/path_null_byte"

# Long paths
python3 -c "
import sys
path = '/' + 'A' * 127  # at MAX_PATH_LEN boundary
sys.stdout.buffer.write(f'GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
" > "$DIR/path_long_127"

python3 -c "
import sys
path = '/' + 'A' * 200  # over MAX_PATH_LEN
sys.stdout.buffer.write(f'GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
" > "$DIR/path_long_200"

# Auth header edge cases
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic \r\n\r\n' > "$DIR/auth_empty_b64"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: \r\n\r\n' > "$DIR/auth_empty"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer token123\r\n\r\n' > "$DIR/auth_bearer"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n' > "$DIR/auth_valid_b64"

# Long auth header
python3 -c "
import sys
auth = 'Basic ' + 'A' * 300
sys.stdout.buffer.write(f'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: {auth}\r\n\r\n'.encode())
" > "$DIR/auth_long_value"

# Auth with colon for extract_basic_auth
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic user:password\r\n\r\n' > "$DIR/auth_with_colon"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic :nouser\r\n\r\n' > "$DIR/auth_empty_user"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic nopass:\r\n\r\n' > "$DIR/auth_empty_pass"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic a:b:c:d:e\r\n\r\n' > "$DIR/auth_multi_colon"

# Origin/Host CSRF checks
printf 'GET / HTTP/1.1\r\nHost: localhost:7681\r\nOrigin: http://evil.com\r\n\r\n' > "$DIR/csrf_mismatch"
printf 'GET / HTTP/1.1\r\nHost: localhost:7681\r\nOrigin: http://localhost:7681\r\n\r\n' > "$DIR/csrf_match"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost:9999\r\n\r\n' > "$DIR/csrf_port_diff"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nOrigin: https://localhost\r\n\r\n' > "$DIR/csrf_scheme_diff"
printf 'GET / HTTP/1.1\r\nHost: target.com\r\nOrigin: http://target.com.evil.com\r\n\r\n' > "$DIR/csrf_subdomain_trick"

# Malformed HTTP
printf 'GARBAGE\r\n\r\n' > "$DIR/malformed_no_space"
printf 'GET\r\n\r\n' > "$DIR/malformed_no_path"
printf '\r\n\r\n' > "$DIR/malformed_empty_line"
printf 'GET / HTTP/1.1\r\nBadHeader\r\n\r\n' > "$DIR/malformed_no_colon"
printf 'GET / HTTP/1.1\r\n: empty-name\r\n\r\n' > "$DIR/malformed_empty_header_name"
printf 'GET / HTTP/1.1\r\nHost:\r\n\r\n' > "$DIR/malformed_empty_header_value"

# No terminating \r\n\r\n
printf 'GET / HTTP/1.1\r\nHost: localhost' > "$DIR/malformed_no_end"

# Lots of headers
python3 -c "
import sys
req = 'GET / HTTP/1.1\r\n'
for i in range(100):
    req += f'X-Header-{i}: value-{i}\r\n'
req += '\r\n'
sys.stdout.buffer.write(req.encode())
" > "$DIR/many_headers"

# Header injection / CRLF injection
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nX-Injected\r\nAuthorization: Basic AAAA\r\n\r\n' > "$DIR/header_injection"
printf 'GET / HTTP/1.1\r\nHost: localhost%%0d%%0aInjected: true\r\n\r\n' > "$DIR/crlf_encoded"

# Format strings in various positions
printf 'GET /%%s%%s%%s%%n HTTP/1.1\r\nHost: %%x%%x%%x\r\nAuthorization: Basic %%n%%n\r\n\r\n' > "$DIR/fmt_everywhere"

# More HTTP methods
printf 'PUT /api HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/method_put"
printf 'DELETE /api HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/method_delete"
printf 'PATCH /api HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/method_patch"
printf 'OPTIONS / HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/method_options"
printf 'HEAD / HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/method_head"
printf 'CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/method_connect"
printf 'TRACE / HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/method_trace"

# HTTP version variations
printf 'GET / HTTP/0.9\r\n\r\n' > "$DIR/http_09"
printf 'GET / HTTP/2.0\r\nHost: localhost\r\n\r\n' > "$DIR/http_20"
printf 'GET / HTTP/9.9\r\nHost: localhost\r\n\r\n' > "$DIR/http_99"

# WebSocket upgrade (relevant to ttyd)
printf 'GET /ws HTTP/1.1\r\nHost: localhost:7681\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' > "$DIR/ws_upgrade"
printf 'GET /ws HTTP/1.1\r\nHost: localhost:7681\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: http://localhost:7681\r\nAuthorization: Basic YWRtaW46cGFzcw==\r\n\r\n' > "$DIR/ws_upgrade_auth"

# Duplicate headers
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46cGFzcw==\r\nAuthorization: Basic d3Jvbmc6d3Jvbmc=\r\n\r\n' > "$DIR/dup_auth_headers"
printf 'GET / HTTP/1.1\r\nHost: evil.com\r\nHost: localhost\r\n\r\n' > "$DIR/dup_host_headers"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nOrigin: http://evil.com\r\nOrigin: http://localhost\r\n\r\n' > "$DIR/dup_origin_headers"

# Very long header names / values
python3 -c "
import sys
name = 'X-' + 'A' * 300
req = f'GET / HTTP/1.1\r\nHost: localhost\r\n{name}: value\r\n\r\n'
sys.stdout.buffer.write(req.encode())
" > "$DIR/long_header_name"

python3 -c "
import sys
value = 'A' * 1000
req = f'GET / HTTP/1.1\r\nHost: localhost\r\nX-Custom: {value}\r\n\r\n'
sys.stdout.buffer.write(req.encode())
" > "$DIR/long_header_value"

# Request with body
printf 'POST /token HTTP/1.1\r\nHost: localhost:7681\r\nContent-Length: 27\r\nContent-Type: application/json\r\n\r\n{"username":"admin","pass":"x"}' > "$DIR/post_with_body"

# ttyd-specific paths
printf 'GET /ws HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/path_ws"
printf 'GET /token HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/path_token"
printf 'GET /auth_token.js HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/path_auth_token_js"
printf 'GET /favicon.ico HTTP/1.1\r\nHost: localhost:7681\r\n\r\n' > "$DIR/path_favicon"

# Tab and space variations in request line
printf 'GET\t/\tHTTP/1.1\r\nHost: localhost\r\n\r\n' > "$DIR/tab_separated"
printf 'GET  /  HTTP/1.1\r\nHost: localhost\r\n\r\n' > "$DIR/double_space_request"

# LF-only line endings (no CR)
printf 'GET / HTTP/1.1\nHost: localhost\nAuthorization: Basic YWRtaW46cGFzcw==\n\n' > "$DIR/lf_only"

echo "[+] Generated $(ls "$DIR" | wc -l) seeds for http_parsing"

###############################################################################
echo
TOTAL=$(find "$SCRIPT_DIR/corpus" -type f | wc -l)
echo "[+] Total corpus: $TOTAL seed files"
echo "[+] Corpus directories:"
echo "    corpus/auth_header/    ($(ls "$SCRIPT_DIR/corpus/auth_header" | wc -l) files)"
echo "    corpus/websocket_auth/ ($(ls "$SCRIPT_DIR/corpus/websocket_auth" | wc -l) files)"
echo "    corpus/http_parsing/   ($(ls "$SCRIPT_DIR/corpus/http_parsing" | wc -l) files)"
