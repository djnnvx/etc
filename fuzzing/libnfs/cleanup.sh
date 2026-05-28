#!/bin/bash
# cleanup.sh - kill fuzzers and remove artifacts.
# Usage: bash cleanup.sh [--keep-corpus] [--keep-builds] [--keep-source] [--crashes-only]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

SESSION="libnfs-fuzz"
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

pkill -u "$(id -un)" -f "afl-fuzz.*fuzz_" 2>/dev/null || true
for h in fuzz_nfs3 fuzz_nfs4 fuzz_mount fuzz_pdu; do
    pkill -u "$(id -un)" -f "${h}" 2>/dev/null || true
done

[[ "${CRASHES_ONLY}" -eq 1 ]] && { ok "Processes killed."; exit 0; }

if [[ "${KEEP_BUILDS}" -eq 0 ]]; then
    for h in fuzz_nfs3 fuzz_nfs4 fuzz_mount fuzz_pdu; do
        rm -f "${h}" "${h}.cmplog" "${h}.repro"
    done
    rm -rf build-cls build-cmplog build-plain
    ok "Binaries and build dirs removed."
fi

if [[ "${KEEP_CORPUS}" -eq 0 ]]; then
    rm -rf corpus/ output/
    ok "Corpus and output removed."
fi

if [[ "${KEEP_SOURCE}" -eq 0 ]]; then
    rm -rf libnfs-src/ AFLplusplus/ afl-build/
    ok "Source trees removed."
fi

ok "Done."
