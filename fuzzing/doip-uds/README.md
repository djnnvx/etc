# doip-uds

Fuzzers and clients for DoIP (ISO 13400) and UDS (ISO 14229) over Ethernet.

| File | What it does |
|---|---|
| `doipstate.py` | Sequence fuzzer. Holds several live connections and mutates the order of operations rather than the bytes. |
| `doipfuzz.py` | One-shot case fuzzer over DoIP headers, routing activation and UDS. |
| `doip.py` | Client. discover, info, send, scan, shell. |
| `doip_tls.py` | Client for DoIP over TLS on 3496. |
| `uds_protection_map.py` | Sweeps all 256 service IDs and classifies each by its negative response code. |

Prefer `doipstate.py`. One-shot cases on fresh connections cannot reach state
that takes a long session to build, and that is where the interesting behaviour
tends to be.

    python3 doipstate.py -t 127.0.0.1 -n 20000 --seed 1 --len 12
    python3 doipstate.py replay sequences/000123_PERSISTED.json

Both fuzzers exclude the UDS services that write, reset or route: `0x2E`,
`0x31`, `0x11`, `0x34`-`0x37`, `0x85`, `0x28`, and `0x27` with an even
subfunction. `doipfuzz.py --unsafe` lifts that. Do not lift it against hardware
you care about.
