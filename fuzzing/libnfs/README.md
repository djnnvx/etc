# libnfs fuzzing

Fuzzing harnesses for **libnfs** (Ronnie Sahlberg's userspace NFSv3 / NFSv4 /
MOUNT / NLM / NSM / PORTMAP / RQUOTA client). Same machine setup as the
libksba/libusb harnesses: AFL++ (CLASSIC + laf-intel), a CmpLog sibling per
harness, ASan + UBSan at `-O0 -g` with `signed-integer-overflow` and `shift`
dropped (XDR's `(v << 8) | next` idiom is pure noise under those checks).

Why libnfs:
- Same profile as libksba. Hand-rolled binary parser, ~87% of commits by one
  person, ubiquitous (VLC `nfs://`, Kodi, gvfs, QEMU block layer, mpd, fio),
  **not on OSS-Fuzz**, no fuzz harness in-tree.
- Attacker model: malicious NFS server. Victim's libnfs client (typically
  invoked via `vlc nfs://attacker/x.mp4` style URLs) sends a request; the
  attacker controls every reply byte.

## Harnesses

| harness     | drives                                      | reach                                  |
|-------------|---------------------------------------------|----------------------------------------|
| `fuzz_nfs3` | per-procedure `zdr_*_3res` decoders (21 of) | NFSv3 reply parsing (most common use)  |
| `fuzz_nfs4` | `zdr_COMPOUND4res`                          | NFSv4 COMPOUND reply (biggest parser)  |
| `fuzz_mount`| `zdr_mountres3`, `zdr_exports`, others      | MOUNT v3 - the auth-less first surface |
| `fuzz_pdu`  | `libnfs_zdr_callmsg` / `libnfs_zdr_replymsg`| RPC framing layer above the decoders   |

The first byte of each input picks the sub-decoder where applicable, so each
corpus is shared across many procedures.

## Usage

```
bash setup.sh            # deps + AFL++ + instrumented libnfs + harnesses + corpus
bash start-fuzzers.sh    # 8 instances in tmux (master + CmpLog secondary per harness)
bash start-fuzzers.sh --status
bash cleanup.sh          # kill + remove artifacts (flags: --keep-corpus --keep-source ...)
```

`setup.sh` flags: `--skip-deps` (deps already installed), `--skip-afl` (use a
system afl-clang-fast instead of building AFL++ from source).

Each harness builds three ways: `H` (AFL persistent), `H.cmplog` (CmpLog), and
`H.repro` (plain clang + ASan, reads files from argv) for crash triage:

```
./fuzz_nfs3.repro output/master_nfs3/crashes/id:000000*
```

## Target version

`setup.sh` defaults to libnfs git tip (6.0.x). To pin to a release:

```
LIBNFS_TAG=libnfs-6.0.1 bash setup.sh
```

## Soft spots flagged before fuzzing (corpus is biased toward these)

The libnfs parsing stack is XDR-shaped: tagged unions everywhere
(accepted-vs-rejected reply, NFS3res ok-vs-fail, NFS4 resop4 by opcode).
Classes of bug worth pre-seeding:

- **Negative/huge length fields** through `zdr_bytes`, `zdr_array`,
  `zdr_string`. XDR length fields are u32; some callers cast to int and
  loop. Trigger: `0xffffffff` in length slot.
- **Tag mismatch** in tagged unions: claim status=NFS3_OK then truncate the
  expected `fattr3` payload, or claim a v4 opcode that doesn't match the
  result body that follows.
- **Linked-list cycles** in MOUNT `exports` / `groups` (each entry has a
  "next" pointer; nothing in the decoder caps traversal depth).

## Notes

- libnfs's ZDR is a re-implementation of Sun XDR; it predates and replaces
  glibc's `tirpc`. Bugs found here may or may not exist upstream in tirpc -
  worth checking once a real crash lands.
- `--without-libkrb5` is set at configure time to avoid the GSSAPI optional
  dep. Krb5-protected NFS isn't reachable for the kind of attacker we care
  about (server-controlled) since the krb5 wrap is verified before the inner
  payload is fed to ZDR.
- `--disable-utils --disable-examples`: skip the bundled tools - they bring
  in unrelated link deps and we only need `libnfs.la`.
