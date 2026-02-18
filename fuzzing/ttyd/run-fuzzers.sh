#!/bin/bash
# Run all TTYD fuzzers in tmux sessions
# Supports: dictionaries, CmpLog, parallel fuzzing
# Safe to detach from SSH - sessions persist in background

set -e

SESSION="ttyd-fuzz"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check dependencies
if ! command -v tmux &> /dev/null; then
    echo "[!] tmux not found. Install with: sudo apt-get install tmux"
    exit 1
fi

if ! command -v afl-fuzz &> /dev/null; then
    echo "[!] afl-fuzz not found. Install AFL++ first."
    exit 1
fi

# Check that harnesses are built
for harness in fuzz_auth_header fuzz_websocket_auth fuzz_http_parsing; do
    if [ ! -x "$SCRIPT_DIR/$harness" ]; then
        echo "[!] $harness not found. Run ./build_fuzzers.sh first."
        exit 1
    fi
done

# Generate corpus if missing
for dir in auth_header websocket_auth http_parsing; do
    if [ ! -d "$SCRIPT_DIR/corpus/$dir" ] || [ -z "$(ls -A "$SCRIPT_DIR/corpus/$dir" 2>/dev/null)" ]; then
        echo "[*] Corpus missing. Run ./build_fuzzers.sh first to generate it."
        exit 1
    fi
done

# Find dictionaries
DICT_DIR=""
for candidate in /usr/share/afl++/dictionaries /usr/local/share/afl++/dictionaries "$SCRIPT_DIR/dictionaries"; do
    if [ -d "$candidate" ]; then
        DICT_DIR="$candidate"
        break
    fi
done

if [ -z "$DICT_DIR" ]; then
    echo "[!] Warning: No AFL++ dictionaries directory found. Running without dictionaries."
    echo "    Expected at: /usr/share/afl++/dictionaries/"
fi

# Calculate core allocation
TOTAL_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
CORES_PER_TARGET=$((TOTAL_CORES / 3))
[ "$CORES_PER_TARGET" -lt 1 ] && CORES_PER_TARGET=1

echo "[*] System: $TOTAL_CORES cores, $CORES_PER_TARGET per target"

# Create output directories
mkdir -p "$SCRIPT_DIR/output/auth_header" "$SCRIPT_DIR/output/websocket_auth" "$SCRIPT_DIR/output/http_parsing"

# Kill existing session if running
tmux kill-session -t "$SESSION" 2>/dev/null || true

echo "[*] Starting fuzzing sessions in tmux session: $SESSION"
echo

# Build afl-fuzz command for a given target
# Usage: build_afl_cmd <harness_name> <corpus_dir> <output_dir> <dict_file> <node_type> [extra_flags]
build_afl_cmd() {
    local harness=$1
    local corpus=$2
    local output=$3
    local dict=$4
    local node_flag=$5
    shift 5
    local extra_flags="$*"

    local cmd="afl-fuzz -i $corpus -o $output $node_flag"

    # Add dictionary if available
    if [ -n "$DICT_DIR" ] && [ -f "$DICT_DIR/$dict" ]; then
        cmd="$cmd -x $DICT_DIR/$dict"
    fi

    # Add any extra flags (e.g., -c for CmpLog)
    if [ -n "$extra_flags" ]; then
        cmd="$cmd $extra_flags"
    fi

    cmd="$cmd -- ./$harness"
    echo "$cmd"
}

# Launch a fuzzing campaign for one target
# Usage: launch_target <window_name> <harness_name> <corpus_dir_name> <dict_file>
launch_target() {
    local window_name=$1
    local harness=$2
    local corpus_dir=$3
    local dict=$4
    local output_dir="output/$corpus_dir"
    local corpus_path="corpus/$corpus_dir"
    local has_cmplog=false

    if [ -x "$SCRIPT_DIR/${harness}_cmplog" ]; then
        has_cmplog=true
    fi

    # Master node
    local master_cmd
    master_cmd=$(build_afl_cmd "$harness" "$corpus_path" "$output_dir" "$dict" "-M main")

    if [ "$window_name" = "auth_header" ]; then
        # First window - create the session
        tmux new-session -d -s "$SESSION" -n "$window_name" \
            "cd '$SCRIPT_DIR' && $master_cmd; read"
    else
        tmux new-window -t "$SESSION" -n "$window_name" \
            "cd '$SCRIPT_DIR' && $master_cmd; read"
    fi

    local node_count=1

    # CmpLog node (if cmplog binary exists)
    if $has_cmplog && [ "$CORES_PER_TARGET" -ge 2 ]; then
        local cmplog_cmd
        cmplog_cmd=$(build_afl_cmd "$harness" "$corpus_path" "$output_dir" "$dict" "-S cmplog" "-c ./${harness}_cmplog")
        tmux split-window -h -t "$SESSION:$window_name" \
            "cd '$SCRIPT_DIR' && $cmplog_cmd; read"
        node_count=$((node_count + 1))
    fi

    # Additional secondary nodes if cores permit
    local remaining=$((CORES_PER_TARGET - node_count))
    for i in $(seq 1 $remaining); do
        local slave_cmd
        slave_cmd=$(build_afl_cmd "$harness" "$corpus_path" "$output_dir" "$dict" "-S slave_$i")
        tmux split-window -v -t "$SESSION:$window_name" \
            "cd '$SCRIPT_DIR' && $slave_cmd; read"
    done

    echo "[+] $window_name: master + $([ $has_cmplog = true ] && [ $CORES_PER_TARGET -ge 2 ] && echo "cmplog + " || true)$((CORES_PER_TARGET - node_count)) secondary nodes"
}

# Launch the three campaigns
launch_target "auth_header"    "fuzz_auth_header"    "auth_header"    "http.dict"
launch_target "websocket_auth" "fuzz_websocket_auth" "websocket_auth" "json.dict"
launch_target "http_parsing"   "fuzz_http_parsing"   "http_parsing"   "http.dict"

# Add a status window
tmux new-window -t "$SESSION" -n "status" \
    "cd '$SCRIPT_DIR' && watch -n 5 'afl-whatsup -s output/ 2>/dev/null || echo \"=== Auth Header ===\"; cat output/auth_header/main/fuzzer_stats 2>/dev/null | grep -E \"(execs_done|execs_per_sec|saved_crashes|saved_hangs|last_find)\"; echo; echo \"=== WebSocket Auth ===\"; cat output/websocket_auth/main/fuzzer_stats 2>/dev/null | grep -E \"(execs_done|execs_per_sec|saved_crashes|saved_hangs|last_find)\"; echo; echo \"=== HTTP Parsing ===\"; cat output/http_parsing/main/fuzzer_stats 2>/dev/null | grep -E \"(execs_done|execs_per_sec|saved_crashes|saved_hangs|last_find)\"'"

# Select first window
tmux select-window -t "$SESSION:0"

echo
echo "[+] All fuzzers started in tmux session: $SESSION"
echo
echo "Commands:"
echo "  tmux attach -t $SESSION          # Attach to session"
echo "  tmux select-window -t $SESSION:0 # auth_header"
echo "  tmux select-window -t $SESSION:1 # websocket_auth"
echo "  tmux select-window -t $SESSION:2 # http_parsing"
echo "  tmux select-window -t $SESSION:3 # status overview"
echo "  Ctrl-b d                         # Detach (fuzzers keep running)"
echo "  tmux kill-session -t $SESSION    # Stop all fuzzers"
echo
echo "[*] You can safely disconnect from SSH. Fuzzers will keep running."
echo "[*] Crashes will be saved in output/*/main/crashes/"
