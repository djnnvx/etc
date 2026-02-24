# usbipd fuzzer

AFL++ fuzzing environment for the USB/IP daemon (`usbipd`) and protocol stack.

Two complementary modes run in parallel:
- **In-process** (fast, ~50k exec/s) — AFL++ calls usbip parsing functions directly with `recv()` intercepted via `--wrap`
- **QEMU network** (deep) — AFL++ sends mutated packets to a live `usbipd` inside a minimal VM; catches kernel-level bugs in the USB/IP module

## Quick start

```bash
bash setup.sh          # install deps, build AFL++, compile kernel, create initramfs (~20 min)
bash build_fuzzers.sh  # compile harnesses (~30 sec)
bash run-fuzzers.sh    # launch tmux session with both fuzzer instances
```

Check status / stop:
```bash
bash run-fuzzers.sh --status   # afl-whatsup summary
bash cleanup.sh                # kill everything
bash cleanup.sh --keep-corpus  # kill procs + rm builds, keep output/
```

Crash backup (run as cron or loop):
```bash
bash backup-crashes.sh         # archives new unique crashes to ./backups/
# crontab: */15 * * * * /path/to/usbip/backup-crashes.sh
```

## Files

| File | Purpose |
|------|---------|
| `setup.sh` | Full bootstrap: deps, AFL++, Linux 6.12, busybox, initramfs |
| `build_fuzzers.sh` | Compile harnesses (fast re-build without re-running setup) |
| `run-fuzzers.sh` | Tmux session: AFL++ master + QEMU worker |
| `backup-crashes.sh` | Timestamped, deduplicated crash archival |
| `cleanup.sh` | Kill processes, remove artifacts |
| `fuzz_protocol.c` | op_common header routing harness |
| `fuzz_devlist.c` | Device-list reply parsing (ndev overflow class) |
| `fuzz_import.c` | Device import + busid string edge cases |
| `fuzz_urb.c` | URB header parsing (CVE-2016-3955 class) |
| `mock_syscalls.c` | `__wrap_recv` / `__wrap_send` — feeds AFL input into usbip source |
| `net_send.c` | TCP client that sends AFL input to usbipd in the QEMU VM |
| `fuzz-include/usbip_fuzz.h` | Fuzz buffer, logging stubs, protocol constants |
| `gen_corpus.py` | Generates 87 structured seeds across 7 categories |
| `dictionaries/usbip.dict` | AFL++ dictionary (op codes, URB flags, busid strings) |
| `qemu/init` | Initramfs `/init`: mounts, loads USB/IP modules, watchdog loops usbipd |
| `qemu/kernel.config` | Minimal kernel config (USB/IP + e1000 + serial, no distro cruft) |

## Architecture

```
AFL++ master ──────────────────► fuzz_protocol (in-process)
                                  recv() → g_fuzz_buf (--wrap)
                                  ASAN crash → AFL++ detects instantly

AFL++ worker ──► net_send ──TCP──► usbipd (QEMU VM, port 13240→3240)
                                  ECONNRESET → exit(1) → AFL++ marks crash
         shared output/ dir
         (corpus cross-pollination)
```

The QEMU VM boots from `bzImage` + `initramfs.cpio.gz` in under 2 seconds. `usbipd` is restarted immediately on crash by the `/init` watchdog, keeping round-trip latency low.

## Notable targets

- `usbip_net_recv_op_common()` — parses the 8-byte op_common header on every connection
- `usbip_net_recv_op_devlist_reply()` — `ndev` integer overflow / large allocation
- `usbip_net_recv_op_import_reply()` — busid string handling (path traversal, no-NUL)
- URB `transfer_buffer_length` validation — CVE-2016-3955 class (heap overflow via unchecked length field in `USBIP_RET_SUBMIT`)
