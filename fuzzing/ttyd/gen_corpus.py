#!/usr/bin/env python3
"""Generate seed corpus for TTYD fuzzing harnesses.

Creates structured binary seeds in corpus/{websocket_auth,http_parsing}/.
Run from the script directory or pass the output base dir as argv[1].

Formats:
  websocket_auth: [has_credential:1][cred_len:2 BE][credential][json_message]
  http_parsing:   [auth_mode:1][cred_len:2 BE][credential][path_len:2 BE][path][auth_header_value]
"""

import os
import sys
import struct

base_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))


def write_seeds(subdir, seeds):
    d = os.path.join(base_dir, "corpus", subdir)
    os.makedirs(d, exist_ok=True)
    for name, data in seeds.items():
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
    print(f"[+] Generated {len(seeds)} seeds for {subdir}")


# ── helpers ──────────────────────────────────────────────────────────────────

def ws_seed(has_cred, cred, json_msg):
    """websocket_auth format: [has_credential:1][cred_len:2 BE][credential][json]"""
    return struct.pack(">B", has_cred) + struct.pack(">H", len(cred)) + cred + json_msg


def http_seed(mode, cred, path, auth=b""):
    """http_parsing format: [mode:1][cred_len:2 BE][cred][path_len:2 BE][path][auth]"""
    return (struct.pack(">B", mode)
            + struct.pack(">H", len(cred)) + cred
            + struct.pack(">H", len(path)) + path
            + auth)


# ── websocket_auth seeds ─────────────────────────────────────────────────────

ws_seeds = {
    "noauth_normal":       ws_seed(0, b"", b'{"columns":80,"rows":24}'),
    "noauth_large_term":   ws_seed(0, b"", b'{"columns":200,"rows":50}'),
    "noauth_empty_json":   ws_seed(0, b"", b"{}"),
    "noauth_with_token":   ws_seed(0, b"", b'{"columns":80,"rows":24,"AuthToken":"ignored"}'),
    "auth_valid":          ws_seed(1, b"admin", b'{"columns":80,"rows":24,"AuthToken":"admin"}'),
    "auth_invalid":        ws_seed(1, b"admin", b'{"columns":80,"rows":24,"AuthToken":"wrong"}'),
    "auth_missing_token":  ws_seed(1, b"admin", b'{"columns":80,"rows":24}'),
    "auth_no_dimensions":  ws_seed(1, b"admin", b'{"AuthToken":"admin"}'),
    "auth_empty_cred":     ws_seed(1, b"",      b'{"columns":80,"rows":24}'),
    "json_malformed":      ws_seed(0, b"", b"{invalid json}"),
    "json_truncated":      ws_seed(0, b"", b'{"columns":'),
    "json_empty":          ws_seed(0, b"", b""),
    "json_array":          ws_seed(1, b"foo", b"[1,2,3]"),
    "json_huge_values":    ws_seed(0, b"", b'{"columns":99999,"rows":99999}'),
    "json_negative":       ws_seed(0, b"", b'{"columns":-1,"rows":-1}'),
    "json_uint16_max":     ws_seed(0, b"", b'{"columns":65535,"rows":65535}'),
    "json_uint16_overflow":ws_seed(0, b"", b'{"columns":65536,"rows":65536}'),
    "json_extra_ws":       ws_seed(0, b"", b'{  "columns" : 80 , "rows" : 24  }'),
    "json_deep_nested":    ws_seed(0, b"", b'{"a":' * 50 + b"1" + b"}" * 50),
    "json_huge_token":     ws_seed(1, b"admin",
                                   b'{"columns":80,"rows":24,"AuthToken":"' + b"A" * 5000 + b'"}'),
    "auth_token_bool":     ws_seed(1, b"admin", b'{"columns":80,"rows":24,"AuthToken":true}'),
    "auth_token_null":     ws_seed(1, b"admin", b'{"columns":80,"rows":24,"AuthToken":null}'),
    "auth_token_int":      ws_seed(1, b"admin", b'{"columns":80,"rows":24,"AuthToken":12345}'),
    "auth_token_dup":      ws_seed(1, b"admin", b'{"AuthToken":"wrong","AuthToken":"admin"}'),
    "auth_long_cred":      ws_seed(1, b"A" * 200,
                                   b'{"AuthToken":"' + b"A" * 200 + b'"}'),
}


# ── http_parsing seeds ───────────────────────────────────────────────────────

B64_CRED = b"YWRtaW46cGFzcw=="

http_seeds = {
    # No auth, various paths
    "noauth_root":        http_seed(0, b"", b"/"),
    "noauth_token":       http_seed(0, b"", b"/token"),
    "noauth_ws":          http_seed(0, b"", b"/ws"),
    "noauth_parent":      http_seed(0, b"", b"/base-path"),
    "noauth_404":         http_seed(0, b"", b"/nonexistent"),
    "noauth_empty_path":  http_seed(0, b"", b""),
    # Path traversal
    "path_traversal":     http_seed(0, b"", b"/../../../etc/passwd"),
    "path_double_slash":  http_seed(0, b"", b"//etc/passwd"),
    "path_dotdot":        http_seed(0, b"", b"/./../../etc/shadow"),
    "path_null":          http_seed(0, b"", b"/\x00hidden"),
    "path_encoded":       http_seed(0, b"", b"/%2e%2e/%2e%2e/etc/passwd"),
    "path_fmt":           http_seed(0, b"", b"/%s%s%s%n"),
    "path_crlf":          http_seed(0, b"", b"/\r\nInjected: header"),
    "path_long":          http_seed(0, b"", b"/" + b"A" * 200),
    # Basic auth — valid
    "basic_valid":        http_seed(1, B64_CRED, b"/", b"Basic " + B64_CRED),
    "basic_token_path":   http_seed(1, B64_CRED, b"/token", b"Basic " + B64_CRED),
    # Basic auth — invalid
    "basic_mismatch":     http_seed(1, B64_CRED, b"/", b"Basic INVALIDBASE64=="),
    "basic_empty":        http_seed(1, B64_CRED, b"/", b"Basic "),
    "basic_no_header":    http_seed(1, B64_CRED, b"/", b""),
    "basic_wrong_scheme": http_seed(1, B64_CRED, b"/", b"Bearer token123"),
    "basic_lowercase":    http_seed(1, B64_CRED, b"/", b"basic " + B64_CRED),
    "basic_uppercase":    http_seed(1, B64_CRED, b"/", b"BASIC " + B64_CRED),
    "basic_dbl_space":    http_seed(1, B64_CRED, b"/", b"Basic  " + B64_CRED),
    "basic_leading_sp":   http_seed(1, B64_CRED, b"/", b" Basic " + B64_CRED),
    "basic_no_cred":      http_seed(1, b"", b"/", b"Basic " + B64_CRED),
    # Boundary (256-byte buf in check_auth)
    "basic_long_auth":    http_seed(1, b"x:y", b"/", b"Basic " + b"A" * 300),
    "basic_boundary_254": http_seed(1, b"x:y", b"/", b"Basic " + b"A" * 248),
    "basic_boundary_256": http_seed(1, b"x:y", b"/", b"Basic " + b"A" * 250),
    # Custom header auth
    "custom_with_value":  http_seed(2, b"", b"/", b"some-token-value"),
    "custom_empty":       http_seed(2, b"", b"/"),
    "custom_token_path":  http_seed(2, b"", b"/token", b"admin"),
    # Format string in auth
    "auth_fmt":           http_seed(1, b"cred", b"/", b"Basic %s%s%s%n%n"),
}


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    write_seeds("websocket_auth", ws_seeds)
    write_seeds("http_parsing", http_seeds)

    total = len(ws_seeds) + len(http_seeds)
    print(f"[+] Total corpus: {total} files")
