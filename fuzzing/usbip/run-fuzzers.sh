#!/bin/bash
# run-fuzzers.sh — launch the usbipd fuzzing environment in a tmux session.
#
# Architecture:
#   Pane 1 (master) — AFL++ master, in-process fuzzing of fuzz_protocol.
#                     High throughput (~50k exec/s), direct crash detection.
#   Pane 2 (worker) — AFL++ secondary, sends mutated packets to usbipd running
#                     inside the QEMU VM via net_send.  Catches kernel-level bugs.
#
# Both instances share the same output/ directory for corpus cross-pollination.
# The QEMU VM boots from bzImage + initramfs.cpio.gz before the worker starts.
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
QEMU_HOST_PORT=13240        # host port forwarded to VM's port 3240
QEMU_MEMORY=256             # MB
QEMU_PID_FILE="${SCRIPT_DIR}/.qemu.pid"
OUTPUT_DIR="${SCRIPT_DIR}/output"
CORPUS_DIR="${SCRIPT_DIR}/corpus"
DICT="${SCRIPT_DIR}/dictionaries/usbip.dict"
TIMEOUT_MASTER=1000         # ms per execution (in-process)
TIMEOUT_WORKER=3000         # ms per execution (network round-trip)

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
        [[ -f "${QEMU_PID_FILE}" ]] && kill "$(cat "${QEMU_PID_FILE}")" 2>/dev/null || true
        rm -f "${QEMU_PID_FILE}"
        ;;
    "") ;;
    *) die "Unknown option: ${1}. Use --rerun or --status." ;;
esac

# ── sanity checks ─────────────────────────────────────────────────────────────
command -v afl-fuzz > /dev/null 2>&1 || die "afl-fuzz not found."
[[ -f "fuzz_protocol"    ]] || die "fuzz_protocol not found. Run build_fuzzers.sh first."
[[ -f "fuzz_protocol.cmplog" ]] || die "fuzz_protocol.cmplog not found."
[[ -f "net_send"         ]] || die "net_send not found. Run setup.sh first."
[[ -f "bzImage"          ]] || die "bzImage not found. Run setup.sh first."
[[ -f "initramfs.cpio.gz" ]] || die "initramfs.cpio.gz not found."
[[ -d "${CORPUS_DIR}"    ]] || die "corpus/ not found. Run setup.sh first."
tmux list-sessions 2>/dev/null | grep -q "${SESSION}" && \
    die "Session '${SESSION}' already running. Use --rerun to restart."

# AFL++ performance settings
sudo sysctl -w kernel.core_pattern=core > /dev/null 2>&1 || true
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || true

mkdir -p "${OUTPUT_DIR}"

# ── launch QEMU VM for the worker pane ────────────────────────────────────────
log "Starting QEMU VM (usbipd on guest port 3240 → host port ${QEMU_HOST_PORT})..."

QEMU_KVM=""
[[ -c /dev/kvm ]] && QEMU_KVM="-enable-kvm -cpu host" && log "KVM available — using hardware acceleration."

qemu-system-x86_64 \
    ${QEMU_KVM} \
    -m ${QEMU_MEMORY}M \
    -smp 1 \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -nographic \
    -append "console=ttyS0 rdinit=/init quiet loglevel=0" \
    -netdev "user,id=n0,hostfwd=tcp::${QEMU_HOST_PORT}-:3240" \
    -device e1000,netdev=n0 \
    -no-reboot \
    -daemonize \
    -pidfile "${QEMU_PID_FILE}"

ok "QEMU started (pid: $(cat "${QEMU_PID_FILE}"))"

# Wait for usbipd to accept connections (max 10 s)
log "Waiting for usbipd to come up..."
for i in $(seq 1 20); do
    if nc -z 127.0.0.1 "${QEMU_HOST_PORT}" 2>/dev/null; then
        ok "usbipd is reachable on port ${QEMU_HOST_PORT}."
        break
    fi
    sleep 0.5
done

# ── create tmux session ───────────────────────────────────────────────────────
log "Creating tmux session '${SESSION}'..."
tmux new-session -d -s "${SESSION}" -x 220 -y 50

# ── Pane 1: AFL++ master (in-process) ─────────────────────────────────────────
log "Launching AFL++ master (in-process fuzz_protocol)..."
tmux send-keys -t "${SESSION}:0.0" \
    "AFL_SKIP_CPUFREQ=1 afl-fuzz \
    -M master \
    -i ${CORPUS_DIR} \
    -o ${OUTPUT_DIR} \
    -x ${DICT} \
    -c ./fuzz_protocol.cmplog \
    -t ${TIMEOUT_MASTER} \
    -- ./fuzz_protocol @@" \
    Enter

# ── Pane 2: AFL++ worker (QEMU network mode) ──────────────────────────────────
log "Launching AFL++ worker (QEMU network via net_send)..."
tmux split-window -v -t "${SESSION}:0"
tmux send-keys -t "${SESSION}:0.1" \
    "AFL_SKIP_CPUFREQ=1 afl-fuzz \
    -S worker \
    -i ${CORPUS_DIR} \
    -o ${OUTPUT_DIR} \
    -x ${DICT} \
    -t ${TIMEOUT_WORKER} \
    -- ./net_send @@ 127.0.0.1 ${QEMU_HOST_PORT}" \
    Enter

# ── attach ────────────────────────────────────────────────────────────────────
ok "Fuzzing session started."
echo ""
echo "  Attach:       tmux attach -t ${SESSION}"
echo "  Status:       ${0} --status"
echo "  Crashes:      ${OUTPUT_DIR}/master/crashes/"
echo "  Stop:         bash cleanup.sh"
echo ""

tmux attach -t "${SESSION}"
