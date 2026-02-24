#!/bin/bash
# cleanup.sh — terminate all fuzzing processes and remove build artifacts.
#
# Options:
#   --keep-corpus    preserve corpus/ and output/ directories
#   --keep-builds    preserve compiled binaries + kernel artifacts
#   --crashes-only   only kill processes, don't remove anything
#
# Usage:
#   bash cleanup.sh                # full cleanup
#   bash cleanup.sh --keep-corpus  # kill procs + rm artifacts, keep fuzzing data

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

SESSION="usbip-fuzz"
QEMU_PID_FILE="${SCRIPT_DIR}/.qemu.pid"

KEEP_CORPUS=0
KEEP_BUILDS=0
CRASHES_ONLY=0

for arg in "$@"; do
    case "${arg}" in
        --keep-corpus)  KEEP_CORPUS=1  ;;
        --keep-builds)  KEEP_BUILDS=1  ;;
        --crashes-only) CRASHES_ONLY=1 ;;
        *) echo "[!] Unknown option: ${arg}" >&2 ;;
    esac
done

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }

# ── kill tmux session ─────────────────────────────────────────────────────────
if tmux list-sessions 2>/dev/null | grep -q "${SESSION}"; then
    log "Killing tmux session '${SESSION}'..."
    tmux kill-session -t "${SESSION}" 2>/dev/null || true
    ok "tmux session killed."
else
    log "No tmux session '${SESSION}' found."
fi

# ── kill QEMU ─────────────────────────────────────────────────────────────────
if [[ -f "${QEMU_PID_FILE}" ]]; then
    QPID="$(cat "${QEMU_PID_FILE}")"
    if kill -0 "${QPID}" 2>/dev/null; then
        log "Killing QEMU (pid ${QPID})..."
        kill "${QPID}" 2>/dev/null || true
        sleep 0.5
        kill -9 "${QPID}" 2>/dev/null || true
        ok "QEMU killed."
    fi
    rm -f "${QEMU_PID_FILE}"
fi

# Kill any stray qemu-system-x86_64 processes belonging to this user
pkill -u "$(id -un)" qemu-system-x86_64 2>/dev/null || true

# ── kill any background AFL++ processes ───────────────────────────────────────
pkill -u "$(id -un)" -f "afl-fuzz.*usbip" 2>/dev/null || true
pkill -u "$(id -un)" -f "fuzz_protocol"   2>/dev/null || true
pkill -u "$(id -un)" -f "fuzz_devlist"    2>/dev/null || true
pkill -u "$(id -un)" -f "fuzz_import"     2>/dev/null || true
pkill -u "$(id -un)" -f "fuzz_urb"        2>/dev/null || true
pkill -u "$(id -un)" -f "net_send"        2>/dev/null || true

if [[ "${CRASHES_ONLY}" -eq 1 ]]; then
    ok "Process cleanup done. (--crashes-only: no files removed)"
    exit 0
fi

# ── remove build artifacts ────────────────────────────────────────────────────
if [[ "${KEEP_BUILDS}" -eq 0 ]]; then
    log "Removing compiled binaries..."
    rm -f fuzz_protocol fuzz_protocol.cmplog
    rm -f fuzz_devlist  fuzz_devlist.cmplog
    rm -f fuzz_import   fuzz_import.cmplog
    rm -f fuzz_urb      fuzz_urb.cmplog
    rm -f usbip_network.o usbip_common.o mock_syscalls.o
    rm -f net_send usbipd-plain

    log "Removing kernel build artifacts..."
    rm -f bzImage initramfs.cpio.gz
    rm -rf initramfs/

    log "Removing source trees (AFL++, kernel, busybox, usbip)..."
    rm -rf AFLplusplus/ afl-build/
    rm -rf "linux-6.12/"          # adjust if KERNEL_VER differs
    rm -rf "busybox-1.36.1/" busybox-install/ busybox/
    rm -rf usbip-src/ usbipd-plain-install/

    ok "Build artifacts removed."
fi

# ── remove fuzzing data ───────────────────────────────────────────────────────
if [[ "${KEEP_CORPUS}" -eq 0 ]]; then
    log "Removing corpus and fuzzing output..."
    rm -rf corpus/ output/
    rm -f .last_backup .seen_crash_hashes .qemu.pid
    ok "Corpus and output removed."
else
    log "Keeping corpus/ and output/ (--keep-corpus)."
fi

ok "Cleanup complete."
