#!/bin/bash
# run-fuzzers.sh — launch the usbipd fuzzing environment in a tmux session.
#
# Layout (2×2 tmux grid):
#   top-left  (master)  — AFL++ master, in-process fuzzing of fuzz_protocol.
#                         Exercises the op_common header dispatcher + reply body
#                         parsers.  CmpLog enabled on master only.
#   top-right (urb)     — AFL++ secondary, in-process fuzzing of fuzz_urb.
#                         Exercises the URB submission / unlink path — the area
#                         where CVE-2016-3955 class (transfer-length overflow) bugs
#                         live.
#   bot-left  (devlist) — AFL++ secondary, in-process fuzzing of fuzz_devlist.
#                         Covers the ndev multiplication overflow and devlist body
#                         parsing paths not reached by fuzz_protocol.
#   bot-right (status)  — afl-whatsup live status (refreshes every 10 s).
#
# CmpLog is enabled only on the master to reduce resource usage
# (was 8 processes = 4 fuzzers × 2 CmpLog; now 4 = 3 fuzzers + 1 CmpLog).
# All instances share output/ for corpus cross-pollination.
#
# QEMU vhci fuzzer (fuzz_vhci_server) must be started separately:
#   See the "QEMU fuzzer" section at the bottom of this script for exact commands.
#
# Prerequisites: setup.sh + build_fuzzers.sh must have completed.
#
# Usage:
#   bash run-fuzzers.sh          # start fresh session
#   bash run-fuzzers.sh --rerun  # kill existing session, start new one
#   bash run-fuzzers.sh --status # show afl-whatsup output

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
DICT="${SCRIPT_DIR}/dictionaries/usbip.dict"
CORPUS_DEVLIST="${CORPUS_DIR}/devlist"
TIMEOUT=1000   # ms per execution (in-process, all instances)
NICE=10        # niceness for afl-fuzz processes (0=normal, 19=lowest priority)

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
die()  { echo "[!] $*" >&2; exit 1; }

# ── option handling ───────────────────────────────────────────────────────────
case "${1:-}" in
    --status)
        command -v afl-whatsup > /dev/null 2>&1 && \
            afl-whatsup "${OUTPUT_DIR}" 2>/dev/null || \
            echo "Output dir: ${OUTPUT_DIR}"
        exit 0 ;;
    --rerun)
        tmux kill-session -t "${SESSION}" 2>/dev/null || true
        ;;
    "") ;;
    *) die "Unknown option: ${1}. Use --rerun or --status." ;;
esac

# ── sanity checks ─────────────────────────────────────────────────────────────
command -v afl-fuzz > /dev/null 2>&1 || die "afl-fuzz not found."
[[ -f "fuzz_protocol"        ]] || die "fuzz_protocol not found. Run build_fuzzers.sh first."
[[ -f "fuzz_protocol.cmplog" ]] || die "fuzz_protocol.cmplog not found."
[[ -f "fuzz_urb"             ]] || die "fuzz_urb not found. Run build_fuzzers.sh first."
[[ -f "fuzz_urb.cmplog"      ]] || die "fuzz_urb.cmplog not found."
[[ -f "fuzz_devlist"         ]] || die "fuzz_devlist not found. Run build_fuzzers.sh first."
[[ -f "fuzz_devlist.cmplog"  ]] || die "fuzz_devlist.cmplog not found."
[[ -d "${CORPUS_PROTOCOL}"   ]] || die "corpus/protocol/ not found. Re-run gen_corpus.py first."
[[ -d "${CORPUS_URB}"        ]] || die "corpus/urb/ not found. Re-run gen_corpus.py first."
[[ -d "${CORPUS_DEVLIST}"    ]] || die "corpus/devlist/ not found. Re-run gen_corpus.py first."
tmux list-sessions 2>/dev/null | grep -q "${SESSION}" && \
    die "Session '${SESSION}' already running. Use --rerun to restart."

# AFL++ performance settings
sudo sysctl -w kernel.core_pattern=core > /dev/null 2>&1 || true
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || true

mkdir -p "${OUTPUT_DIR}"

# ── create tmux session (2×2 grid) ────────────────────────────────────────────
log "Creating tmux session '${SESSION}'..."
tmux new-session -d -s "${SESSION}" -x 220 -y 50

# Build 2×2 layout:
#   split the window into left/right halves, then split each half top/bottom.
#   Result:  0.0 (top-left)  │  0.1 (top-right)
#            0.2 (bot-left)  │  0.3 (bot-right)
tmux split-window -h -t "${SESSION}:0"
tmux split-window -v -t "${SESSION}:0.0"
tmux split-window -v -t "${SESSION}:0.1"

# ── Pane 0.0 (top-left): AFL++ master — fuzz_protocol ─────────────────────────
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

# ── Pane 0.1 (top-right): AFL++ secondary — fuzz_urb ──────────────────────────
log "Launching AFL++ secondary (fuzz_urb — URB submission path)..."
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

# ── Pane 0.2 (bot-left): AFL++ secondary — fuzz_devlist ───────────────────────
log "Launching AFL++ secondary (fuzz_devlist — devlist ndev overflow)..."
tmux send-keys -t "${SESSION}:0.2" \
    "AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 \
    nice -n ${NICE} afl-fuzz \
    -S devlist \
    -i ${CORPUS_DEVLIST} \
    -o ${OUTPUT_DIR} \
    -x ${DICT} \
    -t ${TIMEOUT} \
    -p fast \
    -m none \
    -- ./fuzz_devlist" \
    Enter

# ── Pane 0.3 (bot-right): afl-whatsup live status ────────────────────────────
log "Adding status pane (afl-whatsup)..."
tmux send-keys -t "${SESSION}:0.3" \
    "watch -n 10 '$(command -v afl-whatsup) ${OUTPUT_DIR} 2>/dev/null || echo \"output dir: ${OUTPUT_DIR}\"'" \
    Enter

# ── Window 3: QEMU vhci fuzzer instructions ───────────────────────────────────
#
# fuzz_vhci_server is the ONLY harness that exercises kernel memory (vhci-hcd).
# It requires a running QEMU VM.  Launch it manually:
#
#   STEP 1 — start the QEMU VM (in a separate terminal or tmux pane):
#     qemu-system-x86_64 \
#       -kernel qemu/bzImage \
#       -initrd qemu/initramfs-vhci.cpio.gz \
#       -nographic \
#       -append "console=ttyS0 quiet panic=-1 oops=panic kasan_multi_shot" \
#       -m 512M \
#       -net nic,model=e1000 -net user,hostfwd=tcp:127.0.0.1:13241-:3240
#
#   STEP 2 — once the VM boots and the watchdog starts, launch AFL++:
#     afl-fuzz -S vhci \
#       -i corpus/vhci \
#       -o output \
#       -t 5000 \
#       -x dictionaries/usbip.dict \
#       -- ./fuzz_vhci_server @@ 0.0.0.0 13241
#
#   Enumeration check: in the VM, `lsusb` should show the device and
#   `dmesg | grep snd_usb_audio` should confirm driver binding.
#   ISO URBs: `dmesg | grep usbip` should show EP1 submissions.
#   Crash detection: KASAN + panic_on_oops=1 → VM reboots → ECONNRESET →
#   fuzz_vhci_server exits 1 → AFL++ records crash in output/vhci/crashes/.
#
log "Adding QEMU vhci fuzzer instructions window..."
tmux new-window -t "${SESSION}" -n vhci-howto
tmux send-keys -t "${SESSION}:vhci-howto" \
    "echo '=== QEMU vhci fuzzer ===' && \
     echo 'Step 1: start QEMU VM (see run-fuzzers.sh comments for full command)' && \
     echo 'Step 2: afl-fuzz -S vhci -i corpus/vhci -o output -t 5000 -- ./fuzz_vhci_server @@ 0.0.0.0 13241'" \
    Enter

tmux select-window -t "${SESSION}:0"

# ── attach ────────────────────────────────────────────────────────────────────
ok "Fuzzing session started."
echo ""
echo "  Attach:       tmux attach -t ${SESSION}"
echo "  Status:       ${0} --status"
echo "  Crashes:      ${OUTPUT_DIR}/master/crashes/"
echo "                ${OUTPUT_DIR}/urb/crashes/"
echo "                ${OUTPUT_DIR}/devlist/crashes/"
echo "  QEMU vhci:    see window 'vhci-howto' in tmux session (kernel fuzzing)"
echo "  Stop:         bash cleanup.sh"
echo ""

tmux attach -t "${SESSION}"
