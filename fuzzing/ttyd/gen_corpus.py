#!/usr/bin/env python3
"""Generate seed corpus for TTYD fuzzing harnesses.

Creates structured binary seeds in corpus/{websocket_auth,http_parsing}/.
Run from the script directory or pass the output base dir as argv[1].

Formats:
  websocket_auth: [flags:1][cred_len:2 BE][cred][path_len:1][path]
                  [origin_len:1][origin][host_len:1][host][ws_message]
    flags: bit0=has_cred, bit1=auth_header, bit2=check_origin,
           bit3=url_arg, bit4=writable

  http_parsing:   [auth_mode:1][cred_len:2 BE][cred][path_len:2 BE][path][auth_header_value]
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

def ws_seed(flags, cred, path, origin, host, ws_msg):
    """websocket_auth format:
    [flags:1][cred_len:2 BE][cred][path_len:1][path]
    [origin_len:1][origin][host_len:1][host][ws_message]"""
    return (struct.pack(">B", flags)
            + struct.pack(">H", len(cred)) + cred
            + struct.pack(">B", len(path)) + path
            + struct.pack(">B", len(origin)) + origin
            + struct.pack(">B", len(host)) + host
            + ws_msg)


def http_seed(mode, cred, path, auth=b""):
    """http_parsing format: [mode:1][cred_len:2 BE][cred][path_len:2 BE][path][auth]"""
    return (struct.pack(">B", mode)
            + struct.pack(">H", len(cred)) + cred
            + struct.pack(">H", len(path)) + path
            + auth)


# ── websocket_auth seeds ─────────────────────────────────────────────────────
# Flags: 0x01=has_cred, 0x02=auth_header, 0x04=check_origin, 0x08=url_arg, 0x10=writable

WS = b"/ws"
ORIGIN = b"http://localhost:7681"
HOST = b"localhost:7681"
JSON_AUTH = b'{"columns":80,"rows":24,"AuthToken":"admin"}'
JSON_DIMS = b'{"columns":80,"rows":24}'

ws_seeds = {
    # ── No auth, basic JSON_DATA command ──
    "noauth_json":          ws_seed(0x10, b"", WS, b"", b"", JSON_DIMS),
    "noauth_json_large":    ws_seed(0x10, b"", WS, b"", b"", b'{"columns":200,"rows":50}'),
    "noauth_json_empty":    ws_seed(0x10, b"", WS, b"", b"", b"{}"),
    "noauth_json_malformed":ws_seed(0x10, b"", WS, b"", b"", b"{invalid json}"),

    # ── With credential — JSON_DATA auth flow ──
    "auth_valid":           ws_seed(0x11, b"admin", WS, b"", b"", JSON_AUTH),
    "auth_invalid":         ws_seed(0x11, b"admin", WS, b"", b"",
                                    b'{"columns":80,"rows":24,"AuthToken":"wrong"}'),
    "auth_missing_token":   ws_seed(0x11, b"admin", WS, b"", b"", JSON_DIMS),
    "auth_no_dims":         ws_seed(0x11, b"admin", WS, b"", b"", b'{"AuthToken":"admin"}'),
    "auth_empty_cred":      ws_seed(0x01, b"", WS, b"", b"", JSON_DIMS),
    "auth_token_null":      ws_seed(0x11, b"admin", WS, b"", b"",
                                    b'{"columns":80,"rows":24,"AuthToken":null}'),
    "auth_token_bool":      ws_seed(0x11, b"admin", WS, b"", b"",
                                    b'{"columns":80,"rows":24,"AuthToken":true}'),
    "auth_long_cred":       ws_seed(0x11, b"A" * 200, WS, b"", b"",
                                    b'{"AuthToken":"' + b"A" * 200 + b'"}'),

    # ── Custom auth header (bit 1) ──
    "custom_auth":          ws_seed(0x12, b"someuser", WS, b"", b"", JSON_DIMS),
    "custom_auth_empty":    ws_seed(0x02, b"", WS, b"", b"", JSON_DIMS),

    # ── INPUT command ('0' prefix) ──
    "input_hello":          ws_seed(0x10, b"", WS, b"", b"", b"0hello world"),
    "input_ctrl_c":         ws_seed(0x10, b"", WS, b"", b"", b"0\x03"),
    "input_long":           ws_seed(0x10, b"", WS, b"", b"", b"0" + b"A" * 4096),
    "input_not_writable":   ws_seed(0x00, b"", WS, b"", b"", b"0hello"),

    # ── RESIZE command ('1' prefix) ──
    "resize_normal":        ws_seed(0x10, b"", WS, b"", b"",
                                    b'1{"columns":120,"rows":40}'),
    "resize_huge":          ws_seed(0x10, b"", WS, b"", b"",
                                    b'1{"columns":65535,"rows":65535}'),
    "resize_negative":      ws_seed(0x10, b"", WS, b"", b"",
                                    b'1{"columns":-1,"rows":-1}'),

    # ── PAUSE/RESUME commands ──
    "pause":                ws_seed(0x10, b"", WS, b"", b"", b"2"),
    "resume":               ws_seed(0x10, b"", WS, b"", b"", b"3"),

    # ── Unknown command ──
    "unknown_cmd":          ws_seed(0x10, b"", WS, b"", b"", b"Xunknown"),

    # ── Origin checking (bit 2) ──
    "origin_match":         ws_seed(0x14, b"", WS, ORIGIN, HOST, JSON_DIMS),
    "origin_mismatch":      ws_seed(0x14, b"", WS, b"http://evil.com", HOST, JSON_DIMS),
    "origin_no_host":       ws_seed(0x14, b"", WS, ORIGIN, b"", JSON_DIMS),
    "origin_no_origin":     ws_seed(0x14, b"", WS, b"", HOST, JSON_DIMS),
    "origin_long":          ws_seed(0x14, b"", WS,
                                    b"http://" + b"A" * 200 + b":9999",
                                    b"A" * 200 + b":9999", JSON_DIMS),
    "origin_port_80":       ws_seed(0x14, b"", WS,
                                    b"http://localhost:80", b"localhost", JSON_DIMS),
    "origin_port_443":      ws_seed(0x14, b"", WS,
                                    b"https://localhost:443", b"localhost", JSON_DIMS),

    # ── URL args (bit 3) ──
    "url_arg_enabled":      ws_seed(0x18, b"", WS, b"", b"", b"0echo test"),
    "url_arg_long":         ws_seed(0x18, b"", WS, b"", b"", b"0" + b"X" * 250),

    # ── Path variations ──
    "path_wrong":           ws_seed(0x10, b"", b"/wrong", b"", b"", JSON_DIMS),
    "path_empty":           ws_seed(0x10, b"", b"", b"", b"", JSON_DIMS),
    "path_traversal":       ws_seed(0x10, b"", b"/../ws", b"", b"", JSON_DIMS),
    "path_long":            ws_seed(0x10, b"", b"/" + b"A" * 200, b"", b"", JSON_DIMS),
    "path_null":            ws_seed(0x10, b"", b"/ws\x00extra", b"", b"", JSON_DIMS),

    # ── Auth + origin combined ──
    "auth_origin_valid":    ws_seed(0x15, b"admin", WS, ORIGIN, HOST, JSON_AUTH),
    "auth_origin_invalid":  ws_seed(0x15, b"admin", WS, b"http://evil.com", HOST, JSON_AUTH),

    # ── Empty / minimal ──
    "empty_msg":            ws_seed(0x10, b"", WS, b"", b"", b""),
    "minimal":              ws_seed(0x00, b"", b"", b"", b"", b""),

    # ── JSON edge cases ──
    "json_deep_nested":     ws_seed(0x10, b"", WS, b"", b"",
                                    b'{"a":' * 50 + b"1" + b"}" * 50),
    "json_huge_token":      ws_seed(0x11, b"admin", WS, b"", b"",
                                    b'{"columns":80,"rows":24,"AuthToken":"' + b"A" * 5000 + b'"}'),
    "json_truncated":       ws_seed(0x10, b"", WS, b"", b"", b'{"columns":'),
    "json_extra_ws":        ws_seed(0x10, b"", WS, b"", b"",
                                    b'{  "columns" : 80 , "rows" : 24  }'),
    "json_uint16_overflow": ws_seed(0x10, b"", WS, b"", b"",
                                    b'{"columns":65536,"rows":65536}'),

    # ── Authenticated commands (need JSON_DATA first to auth) ──
    # Note: without auth, non-JSON_DATA commands with credential set get rejected
    "unauth_input":         ws_seed(0x11, b"admin", WS, b"", b"", b"0hello"),
    "unauth_resize":        ws_seed(0x11, b"admin", WS, b"", b"",
                                    b'1{"columns":80,"rows":24}'),
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
