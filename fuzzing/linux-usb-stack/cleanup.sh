#!/bin/bash
# cleanup.sh — terminate all fuzzing processes and optionally remove build artifacts.
#
# Options:
#   --keep-corpus    preserve workdir-*/ (crash data + corpus)
#   --keep-builds    preserve compiled binaries, kernel, syzkaller, initramfs
#   --crashes-only   only kill processes, don't remove anything
#
# Usage:
#   bash cleanup.sh                # full cleanup
#   bash cleanup.sh --keep-corpus  # kill procs + rm artifacts, keep fuzzing data

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

SESSION="usb-fuzz"

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
if tmux list-sessions 2>/dev/null | grep -q "^${SESSION}:"; then
    log "Killing tmux session '${SESSION}'..."
    tmux kill-session -t "${SESSION}" 2>/dev/null || true
    ok "tmux session killed."
else
    log "No tmux session '${SESSION}' found."
fi

# ── kill syz-manager and QEMU ─────────────────────────────────────────────────
pkill -u "$(id -un)" -f "syz-manager"       2>/dev/null || true
pkill -u "$(id -un)" -f "syz-fuzzer"        2>/dev/null || true
pkill -u "$(id -un)" -f "syz-executor"      2>/dev/null || true
pkill -u "$(id -un)" qemu-system-x86_64     2>/dev/null || true

if [[ "${CRASHES_ONLY}" -eq 1 ]]; then
    ok "Process cleanup done. (--crashes-only: no files removed)"
    exit 0
fi

# ── remove build artifacts ────────────────────────────────────────────────────
if [[ "${KEEP_BUILDS}" -eq 0 ]]; then
    log "Removing compiled kernel + initramfs..."
    rm -f bzImage
    rm -f qemu/initramfs.cpio.gz
    rm -rf initramfs/

    log "Removing source trees (kernel, busybox, dropbear, syzkaller, Go)..."
    rm -rf linux/
    rm -rf busybox-*/  busybox-install/
    rm -rf dropbear-*/ dropbear-install/
    rm -rf syzkaller/
    rm -rf go/ gopath/

    log "Removing SSH keys..."
    rm -f qemu/id_rsa qemu/id_rsa.pub

    ok "Build artifacts removed."
fi

# ── remove fuzzing data ───────────────────────────────────────────────────────
if [[ "${KEEP_CORPUS}" -eq 0 ]]; then
    log "Removing workdirs and fuzzing output..."
    rm -rf workdir-raw-gadget/ workdir-gadget-fw/ workdir-usbfs/
    rm -f .last_backup .seen_crash_hashes
    ok "Workdirs removed."
else
    log "Keeping workdir-*/ (--keep-corpus)."
fi

ok "Cleanup complete."
