#!/bin/bash
# start-fuzzers.sh - launch libksba fuzzing in tmux (8 instances across 4 harnesses).
# Each harness gets a -M master (explore) and a -S secondary driven by its CmpLog
# binary. Usage: bash start-fuzzers.sh [--rerun|--status]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

AFL_BIN="${SCRIPT_DIR}/afl-build/usr/local/bin"
[[ -d "${AFL_BIN}" ]] && export PATH="${AFL_BIN}:${PATH}"

SESSION="libksba-fuzz"
OUTPUT="${SCRIPT_DIR}/output"
CORPUS="${SCRIPT_DIR}/corpus"
DICT="${SCRIPT_DIR}/dictionaries/asn1.dict"

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

command -v afl-fuzz > /dev/null 2>&1 || die "afl-fuzz not found. Run setup.sh first."
for h in fuzz_cert fuzz_crl fuzz_ocsp fuzz_cms; do
    [[ -f "${h}" ]]        || die "${h} not found. Run setup.sh first."
    [[ -f "${h}.cmplog" ]] || die "${h}.cmplog not found. Run setup.sh first."
done
tmux list-sessions 2>/dev/null | grep -q "${SESSION}" && \
    die "Session '${SESSION}' already running. Use --rerun."

sudo sysctl -w kernel.core_pattern=core > /dev/null 2>&1 || true
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || true
mkdir -p "${OUTPUT}"

export AFL_SKIP_CPUFREQ=1
export AFL_AUTORESUME=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_DISABLE_TRIM=1
export AFL_KEEP_TIMEOUTS=1
export ASAN_OPTIONS="abort_on_error=1:symbolize=0:detect_leaks=0:allocator_may_return_null=1:detect_stack_use_after_scope=1"
export UBSAN_OPTIONS="print_stacktrace=0:halt_on_error=1"

# role: -M/-S flag; kind: master|cmplog|sec; target+corpus subdir; schedule
afl_cmd() {
    local role="$1" kind="$2" target="$3" corpus_sub="$4" sched="${5:-fast}"
    local cmplog=""
    [[ "${kind}" == "cmplog" ]] && cmplog="-c ./${target}.cmplog -l 2AT"
    echo "afl-fuzz ${role} -i '${CORPUS}/${corpus_sub}' -o '${OUTPUT}' -x '${DICT}' -t 1000 -p ${sched} -m none ${cmplog} -- './${target}'"
}

log "Starting session '${SESSION}'..."
tmux new-session  -d -s "${SESSION}" -n "cert+crl" -x 220 -y 50
tmux split-window -t "${SESSION}:0"   -h
tmux split-window -t "${SESSION}:0.0" -v
tmux split-window -t "${SESSION}:0.2" -v
tmux new-window   -t "${SESSION}" -n "ocsp+cms"
tmux split-window -t "${SESSION}:1"   -h
tmux split-window -t "${SESSION}:1.0" -v
tmux split-window -t "${SESSION}:1.2" -v
tmux new-window   -t "${SESSION}" -n "status"
sleep 0.5

send() { tmux send-keys -t "${SESSION}:${1}.${2}" "${3}" Enter; }

send 0 0 "$(afl_cmd '-M master_cert' master fuzz_cert cert explore)"
send 0 1 "$(afl_cmd '-S sec_cert'    cmplog fuzz_cert cert coe)"
send 0 2 "$(afl_cmd '-M master_crl'  master fuzz_crl  crl  explore)"
send 0 3 "$(afl_cmd '-S sec_crl'     cmplog fuzz_crl  crl  rare)"
send 1 0 "$(afl_cmd '-M master_ocsp' master fuzz_ocsp ocsp explore)"
send 1 1 "$(afl_cmd '-S sec_ocsp'    cmplog fuzz_ocsp ocsp coe)"
send 1 2 "$(afl_cmd '-M master_cms'  master fuzz_cms  cms  explore)"
send 1 3 "$(afl_cmd '-S sec_cms'     cmplog fuzz_cms  cms  lin)"
send 2 0 "watch -n 15 'afl-whatsup ${OUTPUT} 2>/dev/null || echo waiting...'"

ok "Session started. Attach: tmux attach -t ${SESSION}"
