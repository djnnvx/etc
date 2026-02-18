#!/bin/bash
# Clean up TTYD fuzzing artifacts
# Usage: ./clean.sh [--keep-crashes] [--corpus-only]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

KEEP_CRASHES=false
CORPUS_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --keep-crashes) KEEP_CRASHES=true ;;
        --corpus-only)  CORPUS_ONLY=true ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --keep-crashes  Save crash files before cleaning output"
            echo "  --corpus-only   Only clean the corpus directory"
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

# Stop any running fuzzers
if tmux has-session -t ttyd-fuzz 2>/dev/null; then
    echo "[*] Stopping running fuzzer session..."
    tmux kill-session -t ttyd-fuzz
    echo "[+] Fuzzer session killed"
fi

# Clean corpus
if [ -d "$SCRIPT_DIR/corpus" ]; then
    echo "[*] Removing corpus/"
    rm -rf "$SCRIPT_DIR/corpus"
    echo "[+] Corpus removed"
fi

if $CORPUS_ONLY; then
    echo "[+] Done (corpus-only mode)"
    exit 0
fi

# Clean output (fuzzing results)
if [ -d "$SCRIPT_DIR/output" ]; then
    if $KEEP_CRASHES; then
        # Save crashes before cleaning
        CRASH_DIR="$SCRIPT_DIR/saved_crashes_$(date +%Y%m%d_%H%M%S)"
        HAS_CRASHES=false

        for target_dir in "$SCRIPT_DIR"/output/*/; do
            [ -d "$target_dir" ] || continue
            target_name=$(basename "$target_dir")

            for node_dir in "$target_dir"*/; do
                [ -d "$node_dir" ] || continue
                crash_path="$node_dir/crashes"

                if [ -d "$crash_path" ] && [ "$(ls -A "$crash_path" 2>/dev/null)" ]; then
                    node_name=$(basename "$node_dir")
                    dest="$CRASH_DIR/$target_name/$node_name"
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

# Clean compiled binaries
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

if [ "$REMOVED" -gt 0 ]; then
    echo "[+] Removed $REMOVED compiled binaries"
else
    echo "[*] No binaries to remove"
fi

echo "[+] Clean complete"
