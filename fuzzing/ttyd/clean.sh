#!/bin/bash
# Clean up TTYD fuzzing artifacts
#
# Usage: ./clean.sh [OPTIONS]
#   --keep-crashes   Save crash files before cleaning output/
#   --corpus-only    Only clean corpus/, leave everything else
#   --keep-source    Do not remove ttyd-src/ (the git clone)
#   -h, --help

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

KEEP_CRASHES=false
CORPUS_ONLY=false
KEEP_SOURCE=false

for arg in "$@"; do
    case "$arg" in
        --keep-crashes) KEEP_CRASHES=true ;;
        --corpus-only)  CORPUS_ONLY=true ;;
        --keep-source)  KEEP_SOURCE=true ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --keep-crashes  Save crash files before cleaning output/"
            echo "  --corpus-only   Only clean the corpus directory"
            echo "  --keep-source   Keep ttyd-src/ git clone"
            echo "  -h, --help      Show this help"
            exit 0
            ;;
        *)
            echo "[!] Unknown option: $arg"
            echo "    Use --help for usage"
            exit 1
            ;;
    esac
done

# ── stop running fuzzers ──────────────────────────────────────────────────────
if tmux has-session -t ttyd-fuzz 2>/dev/null; then
    echo "[*] Stopping running fuzzer session..."
    tmux kill-session -t ttyd-fuzz
    echo "[+] Fuzzer session killed"
fi

# ── remove crontab entry ──────────────────────────────────────────────────────
CRONTAB_MARKER="# ttyd-fuzz-crash-backup"
CURRENT_CRON=$(crontab -l 2>/dev/null || true)
if echo "$CURRENT_CRON" | grep -q "$CRONTAB_MARKER"; then
    TMPFILE=$(mktemp)
    echo "$CURRENT_CRON" \
        | grep -v "$CRONTAB_MARKER" \
        | grep -v "backup_crashes.sh" \
        > "$TMPFILE" || true
    crontab "$TMPFILE"
    rm -f "$TMPFILE"
    echo "[+] Removed crash-backup crontab entry"
else
    echo "[*] No crash-backup crontab entry found"
fi

# ── clean corpus ──────────────────────────────────────────────────────────────
if [ -d "$SCRIPT_DIR/corpus" ]; then
    echo "[*] Removing corpus/"
    rm -rf "$SCRIPT_DIR/corpus"
    echo "[+] Corpus removed"
fi

if $CORPUS_ONLY; then
    echo "[+] Done (corpus-only mode)"
    exit 0
fi

# ── clean output (optionally save crashes first) ──────────────────────────────
if [ -d "$SCRIPT_DIR/output" ]; then
    if $KEEP_CRASHES; then
        CRASH_DIR="$SCRIPT_DIR/saved_crashes_$(date +%Y%m%d_%H%M%S)"
        HAS_CRASHES=false

        for target_dir in "$SCRIPT_DIR"/output/*/; do
            [ -d "$target_dir" ] || continue
            for node_dir in "$target_dir"*/; do
                [ -d "$node_dir" ] || continue
                crash_path="$node_dir/crashes"
                if [ -d "$crash_path" ] && [ "$(ls -A "$crash_path" 2>/dev/null)" ]; then
                    dest="$CRASH_DIR/$(basename "$target_dir")/$(basename "$node_dir")"
                    mkdir -p "$dest"
                    cp -r "$crash_path"/* "$dest/"
                    HAS_CRASHES=true
                fi
            done
        done

        if $HAS_CRASHES; then
            echo "[+] Crashes saved to: $CRASH_DIR"
        else
            echo "[*] No crashes found to save"
            rmdir "$CRASH_DIR" 2>/dev/null || true
        fi
    fi

    echo "[*] Removing output/"
    rm -rf "$SCRIPT_DIR/output"
    echo "[+] Output removed"
fi

# ── remove compiled harness binaries ─────────────────────────────────────────
REMOVED=0
for binary in fuzz_auth_header fuzz_websocket_auth fuzz_http_parsing; do
    for suffix in "" "_cmplog" "_lf"; do
        target="$SCRIPT_DIR/${binary}${suffix}"
        if [ -f "$target" ]; then
            rm -f "$target"
            REMOVED=$((REMOVED + 1))
        fi
    done
done
[ "$REMOVED" -gt 0 ] && echo "[+] Removed $REMOVED compiled binaries" \
                      || echo "[*] No binaries to remove"

# ── remove generated mock files ───────────────────────────────────────────────
for f in fuzz_lws_mock.c fuzz_lws_mock.h mock_server_globals.c mock_pty_stubs.c backup_crashes.sh; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        rm -f "$SCRIPT_DIR/$f"
        echo "[+] Removed $f"
    fi
done

# ── remove instrumented objects and mock headers ──────────────────────────────
if [ -d "$SCRIPT_DIR/ttyd-obj" ]; then
    echo "[*] Removing ttyd-obj/"
    rm -rf "$SCRIPT_DIR/ttyd-obj"
    echo "[+] ttyd-obj/ removed"
fi

if [ -d "$SCRIPT_DIR/fuzz-include" ]; then
    echo "[*] Removing fuzz-include/"
    rm -rf "$SCRIPT_DIR/fuzz-include"
    echo "[+] fuzz-include/ removed"
fi

# ── optionally remove the ttyd source clone ───────────────────────────────────
if [ -d "$SCRIPT_DIR/ttyd-src" ]; then
    if $KEEP_SOURCE; then
        echo "[*] Keeping ttyd-src/ (--keep-source)"
    else
        echo "[*] Removing ttyd-src/ (pass --keep-source to skip)"
        rm -rf "$SCRIPT_DIR/ttyd-src"
        echo "[+] ttyd-src/ removed"
    fi
fi

# ── remove crash backups log (keep archives — user's decision) ───────────────
if [ -f "$SCRIPT_DIR/crashes-backup/backup.log" ]; then
    rm -f "$SCRIPT_DIR/crashes-backup/backup.log"
    echo "[+] Removed crashes-backup/backup.log"
fi

echo "[+] Clean complete"
