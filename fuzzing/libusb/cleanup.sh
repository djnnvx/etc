#!/bin/bash
# cleanup.sh — kill fuzzers and remove artifacts.
# Usage: bash cleanup.sh [--keep-corpus] [--keep-builds] [--keep-source] [--crashes-only]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

SESSION="libusb-fuzz"
KEEP_CORPUS=0 KEEP_BUILDS=0 KEEP_SOURCE=0 CRASHES_ONLY=0

for arg in "$@"; do
    case "${arg}" in
        --keep-corpus)  KEEP_CORPUS=1  ;;
        --keep-builds)  KEEP_BUILDS=1  ;;
        --keep-source)  KEEP_SOURCE=1  ;;
        --crashes-only) CRASHES_ONLY=1 ;;
        *) echo "[!] Unknown option: ${arg}" >&2 ;;
    esac
done

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }

tmux kill-session -t "${SESSION}" 2>/dev/null || true

pkill -u "$(id -un)" -f "afl-fuzz.*libusb"  2>/dev/null || true
pkill -u "$(id -un)" -f "fuzz_descriptor"    2>/dev/null || true
pkill -u "$(id -un)" -f "fuzz_bos"           2>/dev/null || true
pkill -u "$(id -un)" -f "fuzz_iad"           2>/dev/null || true
pkill -u "$(id -un)" -f "fuzz_usbfs"         2>/dev/null || true

[[ "${CRASHES_ONLY}" -eq 1 ]] && { ok "Processes killed."; exit 0; }

if [[ "${KEEP_BUILDS}" -eq 0 ]]; then
    rm -f fuzz_descriptor fuzz_descriptor.cmplog
    rm -f fuzz_bos        fuzz_bos.cmplog
    rm -f fuzz_iad        fuzz_iad.cmplog
    rm -f fuzz_usbfs      fuzz_usbfs.cmplog
    ok "Binaries removed."
fi

if [[ "${KEEP_CORPUS}" -eq 0 ]]; then
    rm -rf corpus/ output/
    ok "Corpus and output removed."
fi

if [[ "${KEEP_SOURCE}" -eq 0 ]]; then
    rm -rf libusb-src/ AFLplusplus/ afl-build/
    ok "Source trees removed."
fi

ok "Done."
