#!/bin/bash
# run-fuzzers.sh — launch linux-usb-stack syzkaller fuzzing in tmux.
#
# Three fuzzing profiles targeting different USB attack surfaces:
#
#   --raw-gadget  malicious USB device via syz_usb_* + raw_gadget (DEFAULT)
#                 Exercises: USB core descriptor parsing, host controller drivers,
#                 class driver binding on enumeration.
#
#   --gadget-fw   USB gadget framework via configfs syscalls
#                 Exercises: composite gadget, function drivers, gadget lifecycle.
#
#   --usbfs       userspace → kernel via /dev/bus/usb ioctls (usbfs/devio)
#                 Exercises: URB submission/cancellation, control transfers,
#                 concurrent access bugs, ioctl integer overflows.
#
#   --all         all three profiles simultaneously (uses 6 QEMU VMs total)
#
# Usage:
#   bash run-fuzzers.sh [--raw-gadget|--gadget-fw|--usbfs|--all]
#   bash run-fuzzers.sh --status   # show crash counts
#   bash run-fuzzers.sh --rerun    # kill existing session and restart

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

SESSION="usb-fuzz"
PROFILE="raw-gadget"

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
die()  { echo "[!] $*" >&2; exit 1; }

case "${1:-}" in
    --status)
        # Pull Prometheus metrics from each running syz-manager instance.
        # syzkaller exposes /metrics in Prometheus text format — machine-readable,
        # no HTML parsing needed. Falls back to disk-based crash count if the
        # manager isn't responding (e.g. still starting up, or not launched).
        _status_profile() {
            local name="${1}" port="${2}"
            local metrics crash_count corpus_size coverage exec_total uptime

            metrics="$(curl -sf --max-time 2 "http://127.0.0.1:${port}/metrics" 2>/dev/null || true)"

            if [[ -n "${metrics}" ]]; then
                _metric() { echo "${metrics}" | grep "^${1} " | awk '{print $2}' | head -1; }
                crash_count="$(_metric syz_crash_count 2>/dev/null || echo '?')"
                corpus_size="$(_metric syz_corpus_size 2>/dev/null || echo '?')"
                coverage="$(_metric syz_coverage      2>/dev/null || echo '?')"
                exec_total="$(_metric syz_exec_total  2>/dev/null || echo '?')"
                uptime="$(_metric syz_uptime_secs     2>/dev/null || echo '?')"
                printf "  %-12s  UP    crashes=%-4s corpus=%-6s coverage=%-8s execs=%s\n" \
                    "${name}" "${crash_count:-?}" "${corpus_size:-?}" "${coverage:-?}" "${exec_total:-?}"
            else
                # Manager not responding — count crash dirs on disk as fallback
                local disk_crashes=0
                [[ -d "workdir-${name}/crashes" ]] && \
                    disk_crashes=$(find "workdir-${name}/crashes" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
                printf "  %-12s  DOWN  (crashes on disk: %d)\n" "${name}" "${disk_crashes}"
            fi
        }

        echo "=== syzkaller USB stack fuzzer status ==="
        echo ""
        _status_profile "raw-gadget" 56741
        _status_profile "gadget-fw"  56742
        _status_profile "usbfs"      56743
        echo ""
        echo "  Web UIs:  http://127.0.0.1:56741  (raw-gadget)"
        echo "            http://127.0.0.1:56742  (gadget-fw)"
        echo "            http://127.0.0.1:56743  (usbfs)"
        echo ""
        echo "  Tip: curl -s http://127.0.0.1:PORT/metrics | grep '^syz_'"
        exit 0 ;;
    --rerun)
        tmux kill-session -t "${SESSION}" 2>/dev/null || true
        ;;
    --raw-gadget|"")
        PROFILE="raw-gadget" ;;
    --gadget-fw)
        PROFILE="gadget-fw" ;;
    --usbfs)
        PROFILE="usbfs" ;;
    --all)
        PROFILE="all" ;;
    *) die "Unknown option: ${1}. Use --raw-gadget, --gadget-fw, --usbfs, --all, --status, --rerun." ;;
esac

# ── preflight checks ─────────────────────────────────────────────────────────
[[ -x "syzkaller/bin/linux_amd64/syz-manager" ]] || die "syz-manager not found. Run setup.sh first."
[[ -f "bzImage" ]]                               || die "bzImage not found. Run setup.sh first."
[[ -f "qemu/initramfs.cpio.gz" ]]               || die "qemu/initramfs.cpio.gz not found. Run setup.sh first."
[[ -f "qemu/id_rsa" ]]                           || die "qemu/id_rsa not found. Run setup.sh first."
command -v qemu-system-x86_64 > /dev/null        || die "qemu-system-x86_64 not found."

tmux list-sessions 2>/dev/null | grep -q "^${SESSION}:" && \
    die "Session '${SESSION}' already running. Use --rerun to restart or --status to check."

# ── generate config from template (substitute __DIR__ with actual path) ──────
gen_config() {
    local profile="${1}"
    local tmpfile
    tmpfile="$(mktemp /tmp/syz-${profile}-XXXXXX.cfg)"
    sed "s|__DIR__|${SCRIPT_DIR}|g" "${SCRIPT_DIR}/syzkaller-${profile}.cfg" > "${tmpfile}"
    echo "${tmpfile}"
}

# ── launch a single syz-manager instance in a named tmux window ──────────────
launch_profile() {
    local profile="${1}"
    local cfg
    cfg="$(gen_config "${profile}")"

    mkdir -p "workdir-${profile}"

    local port
    case "${profile}" in
        raw-gadget) port=56741 ;;
        gadget-fw)  port=56742 ;;
        usbfs)      port=56743 ;;
    esac

    log "Launching syz-manager for profile '${profile}' (http://127.0.0.1:${port})..."
    tmux new-window -t "${SESSION}" -n "${profile}"
    tmux send-keys -t "${SESSION}:${profile}" \
        "${SCRIPT_DIR}/syzkaller/bin/linux_amd64/syz-manager -config ${cfg}" \
        Enter
}

# ── create tmux session ───────────────────────────────────────────────────────
log "Creating tmux session '${SESSION}'..."
tmux new-session -d -s "${SESSION}" -x 220 -y 50

# The first window is created automatically; rename it to match the first profile.
# We'll use it for the status monitor.

if [[ "${PROFILE}" == "all" ]]; then
    launch_profile "raw-gadget"
    launch_profile "gadget-fw"
    launch_profile "usbfs"
else
    launch_profile "${PROFILE}"
fi

# ── status window ─────────────────────────────────────────────────────────────
tmux rename-window -t "${SESSION}:0" "status"
tmux send-keys -t "${SESSION}:status" \
    "watch -n 15 'bash ${SCRIPT_DIR}/run-fuzzers.sh --status'" \
    Enter

tmux select-window -t "${SESSION}:status"

ok "Fuzzing session started."
echo ""
echo "  Attach:    tmux attach -t ${SESSION}"
echo "  Status:    ${0} --status"
echo "  Profile:   ${PROFILE}"
echo ""
case "${PROFILE}" in
    raw-gadget) echo "  Web UI:    http://127.0.0.1:56741" ;;
    gadget-fw)  echo "  Web UI:    http://127.0.0.1:56742" ;;
    usbfs)      echo "  Web UI:    http://127.0.0.1:56743" ;;
    all)        echo "  Web UIs:   http://127.0.0.1:56741  (raw-gadget)"
                echo "             http://127.0.0.1:56742  (gadget-fw)"
                echo "             http://127.0.0.1:56743  (usbfs)" ;;
esac
echo "  Crashes:   workdir-*/crashes/"
echo "  Stop:      bash cleanup.sh"
echo ""

tmux attach -t "${SESSION}"
