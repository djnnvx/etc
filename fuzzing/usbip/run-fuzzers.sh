#!/bin/bash
# run-fuzzers.sh — launch USB/IP fuzzing in tmux with a 2-fuzzer budget.
#
# Default profile (max-impact):
#   Pane 1: in-process fuzz_urb (fast, high exec/sec, CmpLog-enabled)
#   Pane 2: vhci kernel fuzzer (fuzz_vhci_server) against QEMU VM
#
# Optional profile:
#   --inproc  : protocol + urb only (no QEMU)
#   --stub    : fuzz_urb + stub kernel fuzzer (fuzz_stub_client) against QEMU VM
#
# This script intentionally keeps only two AFL++ instances active.
# For vhci mode it also launches a helper QEMU window in the same tmux session.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

AFL_BIN="${SCRIPT_DIR}/afl-build/usr/local/bin"
[[ -d "${AFL_BIN}" ]] && export PATH="${AFL_BIN}:${PATH}"

SESSION="usbip-fuzz"
OUTPUT_DIR="${SCRIPT_DIR}/output"
CORPUS_DIR="${SCRIPT_DIR}/corpus"
CORPUS_PROTOCOL="${CORPUS_DIR}/protocol"
CORPUS_URB="${CORPUS_DIR}/urb"
CORPUS_VHCI="${CORPUS_DIR}/vhci"
CORPUS_STUB="${CORPUS_DIR}/stub"
DICT="${SCRIPT_DIR}/dictionaries/usbip.dict"
TIMEOUT=1000
VHCI_TIMEOUT=5000
STUB_TIMEOUT=5000
NICE=10
PROFILE="max-impact"
VMLINUX="${SCRIPT_DIR}/bzImage"
VMLINUX_QEMU="${SCRIPT_DIR}/qemu/bzImage"
INITRD_VHCI="${SCRIPT_DIR}/initramfs-vhci.cpio.gz"
INITRD_VHCI_QEMU="${SCRIPT_DIR}/qemu/initramfs-vhci.cpio.gz"
INITRD_SERVER="${SCRIPT_DIR}/initramfs.cpio.gz"
INITRD_SERVER_QEMU="${SCRIPT_DIR}/qemu/initramfs.cpio.gz"

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
die()  { echo "[!] $*" >&2; exit 1; }

case "${1:-}" in
    --status)
        command -v afl-whatsup > /dev/null 2>&1 && \
            afl-whatsup "${OUTPUT_DIR}" 2>/dev/null || \
            echo "Output dir: ${OUTPUT_DIR}"
        exit 0 ;;
    --rerun)
        tmux kill-session -t "${SESSION}" 2>/dev/null || true
        ;;
    --inproc)
        PROFILE="inproc"
        ;;
    --stub)
        PROFILE="stub"
        ;;
    --max-impact|"")
        ;;
    *) die "Unknown option: ${1}. Use --rerun, --status, --inproc, --stub, --max-impact." ;;
esac

command -v afl-fuzz > /dev/null 2>&1 || die "afl-fuzz not found."
[[ -f "fuzz_urb" ]] || die "fuzz_urb not found. Run build_fuzzers.sh first."
[[ -f "fuzz_urb.cmplog" ]] || die "fuzz_urb.cmplog not found."
[[ -d "${CORPUS_URB}" ]] || die "corpus/urb/ not found. Re-run gen_corpus.py first."
tmux list-sessions 2>/dev/null | grep -q "${SESSION}" && \
    die "Session '${SESSION}' already running. Use --rerun to restart."

sudo sysctl -w kernel.core_pattern=core > /dev/null 2>&1 || true
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || true

mkdir -p "${OUTPUT_DIR}"

if [[ "${PROFILE}" == "max-impact" || "${PROFILE}" == "stub" ]]; then
    if [[ -f "${VMLINUX}" ]]; then
        KERNEL_PATH="${VMLINUX}"
    elif [[ -f "${VMLINUX_QEMU}" ]]; then
        KERNEL_PATH="${VMLINUX_QEMU}"
    else
        die "Kernel image not found (expected bzImage or qemu/bzImage)."
    fi
fi

if [[ "${PROFILE}" == "max-impact" ]]; then
    [[ -f "fuzz_vhci_server" ]] || die "fuzz_vhci_server not found. Run build_fuzzers.sh first."
    [[ -d "${CORPUS_VHCI}" ]] || die "corpus/vhci/ not found. Re-run gen_corpus.py first."

    if [[ -f "${INITRD_VHCI}" ]]; then
        INITRD_PATH="${INITRD_VHCI}"
    elif [[ -f "${INITRD_VHCI_QEMU}" ]]; then
        INITRD_PATH="${INITRD_VHCI_QEMU}"
    else
        die "initramfs-vhci.cpio.gz not found. Re-run setup.sh."
    fi
fi

if [[ "${PROFILE}" == "stub" ]]; then
    [[ -f "fuzz_stub_client" ]] || die "fuzz_stub_client not found. Run build_fuzzers.sh first."
    [[ -d "${CORPUS_STUB}" ]] || die "corpus/stub/ not found. Re-run gen_corpus.py first."

    if [[ -f "${INITRD_SERVER}" ]]; then
        INITRD_PATH="${INITRD_SERVER}"
    elif [[ -f "${INITRD_SERVER_QEMU}" ]]; then
        INITRD_PATH="${INITRD_SERVER_QEMU}"
    else
        die "initramfs.cpio.gz not found. Re-run setup.sh."
    fi
fi

log "Creating tmux session '${SESSION}'..."
tmux new-session -d -s "${SESSION}" -x 220 -y 50
tmux split-window -h -t "${SESSION}:0"

if [[ "${PROFILE}" == "inproc" ]]; then
    [[ -f "fuzz_protocol" ]] || die "fuzz_protocol not found. Run build_fuzzers.sh first."
    [[ -f "fuzz_protocol.cmplog" ]] || die "fuzz_protocol.cmplog not found."
    [[ -d "${CORPUS_PROTOCOL}" ]] || die "corpus/protocol/ not found. Re-run gen_corpus.py first."

    log "Launching AFL++ master (fuzz_protocol)..."
    tmux send-keys -t "${SESSION}:0.0" \
        "AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 \
        nice -n ${NICE} afl-fuzz \
        -M master \
        -i ${CORPUS_PROTOCOL} \
        -o ${OUTPUT_DIR} \
        -x ${DICT} \
        -c ./fuzz_protocol.cmplog \
        -t ${TIMEOUT} \
        -p fast \
        -m none \
        -- ./fuzz_protocol" \
        Enter

    log "Launching AFL++ secondary (fuzz_urb)..."
    tmux send-keys -t "${SESSION}:0.1" \
        "AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 \
        nice -n ${NICE} afl-fuzz \
        -S urb \
        -i ${CORPUS_URB} \
        -o ${OUTPUT_DIR} \
        -x ${DICT} \
        -t ${TIMEOUT} \
        -p fast \
        -m none \
        -- ./fuzz_urb" \
        Enter
elif [[ "${PROFILE}" == "max-impact" ]]; then
    log "Launching AFL++ master (fuzz_urb, in-process lane)..."
    tmux send-keys -t "${SESSION}:0.0" \
        "AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 \
        nice -n ${NICE} afl-fuzz \
        -M master \
        -i ${CORPUS_URB} \
        -o ${OUTPUT_DIR} \
        -x ${DICT} \
        -c ./fuzz_urb.cmplog \
        -t ${TIMEOUT} \
        -p fast \
        -m none \
        -- ./fuzz_urb" \
        Enter

    log "Launching AFL++ secondary (fuzz_vhci_server, kernel lane)..."
    tmux send-keys -t "${SESSION}:0.1" \
        "AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        nice -n ${NICE} afl-fuzz \
        -S vhci \
        -i ${CORPUS_VHCI} \
        -o ${OUTPUT_DIR} \
        -x ${DICT} \
        -t ${VHCI_TIMEOUT} \
        -m none \
        -- ./fuzz_vhci_server @@ 0.0.0.0 13241" \
        Enter

    log "Starting vhci QEMU VM window..."
    tmux new-window -t "${SESSION}" -n vm-vhci
    tmux send-keys -t "${SESSION}:vm-vhci" \
        "qemu-system-x86_64 \
        -kernel ${KERNEL_PATH} \
        -initrd ${INITRD_PATH} \
        -nographic \
        -append 'console=ttyS0 quiet panic=-1 oops=panic kasan_multi_shot' \
        -m 512M \
        -net nic,model=e1000 -net user" \
        Enter
else
    log "Launching AFL++ master (fuzz_urb, in-process lane)..."
    tmux send-keys -t "${SESSION}:0.0" \
        "AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 \
        nice -n ${NICE} afl-fuzz \
        -M master \
        -i ${CORPUS_URB} \
        -o ${OUTPUT_DIR} \
        -x ${DICT} \
        -c ./fuzz_urb.cmplog \
        -t ${TIMEOUT} \
        -p fast \
        -m none \
        -- ./fuzz_urb" \
        Enter

    log "Launching AFL++ secondary (fuzz_stub_client, kernel lane)..."
    tmux send-keys -t "${SESSION}:0.1" \
        "AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        nice -n ${NICE} afl-fuzz \
        -S stub \
        -i ${CORPUS_STUB} \
        -o ${OUTPUT_DIR} \
        -x ${DICT} \
        -t ${STUB_TIMEOUT} \
        -m none \
        -- ./fuzz_stub_client @@ 127.0.0.1 13240" \
        Enter

    log "Starting stub QEMU VM window..."
    tmux new-window -t "${SESSION}" -n vm-stub
    tmux send-keys -t "${SESSION}:vm-stub" \
        "qemu-system-x86_64 \
        -kernel ${KERNEL_PATH} \
        -initrd ${INITRD_PATH} \
        -nographic \
        -append 'console=ttyS0 quiet panic=-1 oops=panic kasan_multi_shot' \
        -m 512M \
        -net nic,model=e1000 -net user,hostfwd=tcp:127.0.0.1:13240-:3240" \
        Enter
fi

log "Adding status window..."
tmux new-window -t "${SESSION}" -n status
tmux send-keys -t "${SESSION}:status" \
    "watch -n 10 '$(command -v afl-whatsup) ${OUTPUT_DIR} 2>/dev/null || echo \"output dir: ${OUTPUT_DIR}\"'" \
    Enter

tmux select-window -t "${SESSION}:0"

ok "Fuzzing session started."
echo ""
echo "  Attach:       tmux attach -t ${SESSION}"
echo "  Status:       ${0} --status"
echo "  Profile:      ${PROFILE}"
echo "  Crashes:      ${OUTPUT_DIR}/master/crashes/"
[[ "${PROFILE}" == "inproc" ]] && echo "                ${OUTPUT_DIR}/urb/crashes/"
[[ "${PROFILE}" == "max-impact" ]] && echo "                ${OUTPUT_DIR}/vhci/crashes/"
[[ "${PROFILE}" == "max-impact" ]] && echo "  QEMU console: tmux window 'vm-vhci'"
[[ "${PROFILE}" == "stub" ]] && echo "                ${OUTPUT_DIR}/stub/crashes/"
[[ "${PROFILE}" == "stub" ]] && echo "  QEMU console: tmux window 'vm-stub'"
echo "  Stop:         bash cleanup.sh"
echo ""

tmux attach -t "${SESSION}"
