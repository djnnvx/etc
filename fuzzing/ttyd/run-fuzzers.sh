#!/bin/bash
# Run all TTYD fuzzers in tmux
# Two visible panes (one main per target), cmplog + secondaries run headless
# Safe to detach from SSH - everything persists in background

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
for harness in fuzz_websocket_auth fuzz_http_parsing; do
    if [ ! -x "$SCRIPT_DIR/$harness" ]; then
        echo "[!] $harness not found. Run ./build_fuzzers.sh first."
        exit 1
    fi
done

# Generate corpus if missing
for dir in websocket_auth http_parsing; do
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
    echo "[!] Warning: No AFL++ dictionaries directory found."
fi

# Calculate core allocation
TOTAL_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
CORES_PER_TARGET=$((TOTAL_CORES / 2))
[ "$CORES_PER_TARGET" -lt 1 ] && CORES_PER_TARGET=1

echo "[*] System: $TOTAL_CORES cores, $CORES_PER_TARGET per target"

# Create output directories
mkdir -p "$SCRIPT_DIR/output/websocket_auth" "$SCRIPT_DIR/output/http_parsing"

# Kill existing session if running
tmux kill-session -t "$SESSION" 2>/dev/null || true

echo "[*] Starting fuzzing in tmux session: $SESSION"
echo

# Build afl-fuzz command
build_afl_cmd() {
    local harness=$1 corpus=$2 output=$3 dict=$4 node_flag=$5
    shift 5
    local extra="$*"
    local cmd="afl-fuzz -i $corpus -o $output $node_flag"
    [ -n "$DICT_DIR" ] && [ -f "$DICT_DIR/$dict" ] && cmd="$cmd -x $DICT_DIR/$dict"
    [ -n "$extra" ] && cmd="$cmd $extra"
    cmd="$cmd -- ./$harness"
    echo "$cmd"
}

# Custom mutator for http_parsing
HTTP_ENV=""
if [ -f "$SCRIPT_DIR/http_mutator.so" ]; then
    HTTP_ENV="AFL_CUSTOM_MUTATOR_LIBRARY=$SCRIPT_DIR/http_mutator.so"
    echo "[+] Using custom HTTP mutator for http_parsing"
fi

# ── Launch headless background nodes ──────────────────────────────────────────
# These run without a UI pane — they sync via the shared output dir
BG_PIDS=()

launch_bg() {
    local env_prefix="$1"
    local cmd="$2"
    local logfile="$3"
    (cd "$SCRIPT_DIR" && AFL_NO_UI=1 $env_prefix $cmd > "$logfile" 2>&1) &
    BG_PIDS+=($!)
}

bg_count=0

for target_info in "fuzz_websocket_auth|websocket_auth|json.dict|" "fuzz_http_parsing|http_parsing|http.dict|$HTTP_ENV"; do
    IFS='|' read -r harness corpus_dir dict env_prefix <<< "$target_info"
    output="output/$corpus_dir"
    corpus="corpus/$corpus_dir"
    logdir="$SCRIPT_DIR/output/$corpus_dir"

    # CmpLog secondary (if binary exists and we have cores)
    if [ -x "$SCRIPT_DIR/${harness}_cmplog" ] && [ "$CORES_PER_TARGET" -ge 2 ]; then
        cmd=$(build_afl_cmd "$harness" "$corpus" "$output" "$dict" "-S cmplog" "-c ./${harness}_cmplog")
        launch_bg "$env_prefix" "$cmd" "$logdir/cmplog.log"
        bg_count=$((bg_count + 1))
    fi

    # Extra secondaries
    used=2  # main + cmplog
    remaining=$((CORES_PER_TARGET - used))
    for i in $(seq 1 $remaining); do
        cmd=$(build_afl_cmd "$harness" "$corpus" "$output" "$dict" "-S sec_$i")
        launch_bg "$env_prefix" "$cmd" "$logdir/sec_$i.log"
        bg_count=$((bg_count + 1))
    done
done

echo "[*] Launched $bg_count headless secondary nodes"

# ── Create tmux: 2 panes (main nodes with UI) ────────────────────────────────
ws_main=$(build_afl_cmd "fuzz_websocket_auth" "corpus/websocket_auth" "output/websocket_auth" "json.dict" "-M main")
http_main=$(build_afl_cmd "fuzz_http_parsing" "corpus/http_parsing" "output/http_parsing" "http.dict" "-M main")

tmux new-session -d -s "$SESSION" -n "fuzzers" \
    "cd '$SCRIPT_DIR' && $ws_main; echo '[!] Fuzzer exited'; read"
tmux split-window -h -t "$SESSION:fuzzers" \
    "cd '$SCRIPT_DIR' && $HTTP_ENV $http_main; echo '[!] Fuzzer exited'; read"

# ── Status window ─────────────────────────────────────────────────────────────
tmux new-window -t "$SESSION" -n "status" \
    "cd '$SCRIPT_DIR' && watch -n 10 'echo \"=== WebSocket Auth ===\"; echo; afl-whatsup -s output/websocket_auth 2>&1; echo; echo \"=== HTTP Parsing ===\"; echo; afl-whatsup -s output/http_parsing 2>&1'"

# Select fuzzers window
tmux select-window -t "$SESSION:fuzzers"

# Save background PIDs so clean.sh can kill them
printf '%s\n' "${BG_PIDS[@]}" > "$SCRIPT_DIR/.bg_fuzz_pids"

echo
echo "[+] All fuzzers started in tmux session: $SESSION"
echo "    2 main nodes (visible) + $bg_count headless secondaries"
echo
echo "Commands:"
echo "  tmux attach -t $SESSION          # Attach to session"
echo "  Ctrl-b d                         # Detach (fuzzers keep running)"
echo "  tmux kill-session -t $SESSION    # Stop all fuzzers"
echo
echo "[*] You can safely disconnect from SSH. Fuzzers will keep running."
echo "[*] Crashes will be saved in output/*/main/crashes/"
