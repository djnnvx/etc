#!/bin/bash
# run-all.sh — launch libusb fuzzing in tmux (8 instances across 4 harnesses).
# Usage: bash run-all.sh [--rerun|--status]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

AFL_BIN="${SCRIPT_DIR}/afl-build/usr/local/bin"
[[ -d "${AFL_BIN}" ]] && export PATH="${AFL_BIN}:${PATH}"

SESSION="libusb-fuzz"
OUTPUT="${SCRIPT_DIR}/output"
CORPUS="${SCRIPT_DIR}/corpus"
DICT="${SCRIPT_DIR}/dictionaries/usb.dict"

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }
die() { echo "[!] $*" >&2; exit 1; }

case "${1:-}" in
    --status)
        afl-whatsup "${OUTPUT}" 2>/dev/null || echo "Output: ${OUTPUT}"
        exit 0 ;;
    --rerun)
        tmux kill-session -t "${SESSION}" 2>/dev/null || true ;;
    "") ;;
    *) die "Unknown option: ${1}" ;;
esac

command -v afl-fuzz > /dev/null 2>&1 || die "afl-fuzz not found."
for h in fuzz_descriptor fuzz_bos fuzz_iad fuzz_usbfs; do
    [[ -f "${h}" ]]        || die "${h} not found. Run setup.sh first."
    [[ -f "${h}.cmplog" ]] || die "${h}.cmplog not found."
done
tmux list-sessions 2>/dev/null | grep -q "${SESSION}" && \
    die "Session '${SESSION}' already running. Use --rerun."

sudo sysctl -w kernel.core_pattern=core > /dev/null 2>&1 || true
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || true
mkdir -p "${OUTPUT}"

export AFL_SKIP_CPUFREQ=1
export AFL_AUTORESUME=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export ASAN_OPTIONS="abort_on_error=1:symbolize=0:detect_leaks=0:allocator_may_return_null=1"
export UBSAN_OPTIONS="print_stacktrace=0:halt_on_error=1"

afl_cmd() {
    local role="$1" flag="$2" target="$3" corpus_sub="$4"
    local cmplog=""
    [[ "${flag}" == "master" ]] && cmplog="-c ./${target}.cmplog"
    echo "afl-fuzz ${role} -i '${CORPUS}/${corpus_sub}' -o '${OUTPUT}' -x '${DICT}' -t 500 -p fast -m none ${cmplog} -- './${target}'"
}

log "Starting session '${SESSION}'..."
tmux new-session  -d -s "${SESSION}" -n "desc+bos" -x 220 -y 50
tmux split-window -t "${SESSION}:0"   -h
tmux split-window -t "${SESSION}:0.0" -v
tmux split-window -t "${SESSION}:0.2" -v
tmux new-window   -t "${SESSION}" -n "iad+usbfs"
tmux split-window -t "${SESSION}:1"   -h
tmux split-window -t "${SESSION}:1.0" -v
tmux split-window -t "${SESSION}:1.2" -v
tmux new-window   -t "${SESSION}" -n "status"
sleep 0.5

send() { tmux send-keys -t "${SESSION}:${1}.${2}" "${3}" Enter; }

send 0 0 "$(afl_cmd '-M master_descriptor' master fuzz_descriptor descriptor)"
send 0 1 "$(afl_cmd '-S sec_descriptor'    sec    fuzz_descriptor descriptor)"
send 0 2 "$(afl_cmd '-M master_bos'        master fuzz_bos        bos)"
send 0 3 "$(afl_cmd '-S sec_bos'           sec    fuzz_bos        bos)"
send 1 0 "$(afl_cmd '-M master_iad'        master fuzz_iad        iad)"
send 1 1 "$(afl_cmd '-S sec_iad'           sec    fuzz_iad        iad)"
send 1 2 "$(afl_cmd '-M master_usbfs'      master fuzz_usbfs      usbfs)"
send 1 3 "$(afl_cmd '-S sec_usbfs'         sec    fuzz_usbfs      usbfs)"
send 2 0 "watch -n 15 'afl-whatsup ${OUTPUT} 2>/dev/null || echo waiting...'"

ok "Session started. Attach: tmux attach -t ${SESSION}"
