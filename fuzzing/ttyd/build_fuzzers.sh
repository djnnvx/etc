#!/bin/bash
# Build TTYD fuzzing harnesses
#
# What this script does:
#   1. Installs build dependencies
#   2. Clones ttyd source + runs cmake (for validation & compile_commands.json)
#   3. Generates mock headers/stubs so ttyd's .c files compile without real lws/uv
#   4. Compiles instrumented ttyd objects (http.c, protocol.c, utils.c)
#   5. Builds AFL++ harnesses that #include the real ttyd source files
#   6. Sets up AFL++ dictionaries (download from AFL++ repo, fall back to custom)
#   7. Generates seed corpus
#   8. Installs a crontab entry to back up crashes every 15 minutes
#
# Usage: ./build_fuzzers.sh [afl|libfuzzer]
#
# Note: gen-corpus.sh is merged into this script and is no longer separate.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-afl}"
SANITIZER="address,undefined"

TTYD_SRC="$SCRIPT_DIR/ttyd-src"
TTYD_OBJ="$SCRIPT_DIR/ttyd-obj"
FUZZ_INCLUDE="$SCRIPT_DIR/fuzz-include"
CRONTAB_MARKER="# ttyd-fuzz-crash-backup"
BACKUP_SCRIPT="$SCRIPT_DIR/backup_crashes.sh"

echo "[*] Building TTYD fuzzing harnesses"
echo "[*] Mode:      $MODE"
echo "[*] Sanitizer: $SANITIZER"
echo "[*] Script:    $SCRIPT_DIR"
echo

# ─── 1. dependency install ────────────────────────────────────────────────────

install_deps() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] Warning: Not running as root. Skipping apt-get installs."
        echo "    If builds fail, run: sudo apt-get install afl++ libjson-c-dev"
        echo "    cmake git libwebsockets-dev libuv1-dev pkg-config"
        return
    fi

    local DEPS="libjson-c-dev cmake git pkg-config"
    if [ "$MODE" = "afl" ]; then
        DEPS="$DEPS afl++"
    else
        DEPS="$DEPS clang"
    fi

    local MISSING=""
    for pkg in $DEPS; do
        dpkg -s "$pkg" &>/dev/null || MISSING="$MISSING $pkg"
    done

    if [ -n "$MISSING" ]; then
        echo "[*] Installing:$MISSING"
        apt-get install -y --no-install-recommends $MISSING
        echo "[+] Dependencies installed"
    fi

    # System tuning for AFL++
    if [ "$MODE" = "afl" ]; then
        local CORE_PATTERN
        CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "")
        if [[ "$CORE_PATTERN" == "|"* ]]; then
            echo core > /proc/sys/kernel/core_pattern
            echo "[+] core_pattern set to 'core'"
        fi
        for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            [ -f "$gov" ] && echo performance > "$gov" 2>/dev/null || true
        done
    fi
}

# ─── 2. clone + cmake ttyd ────────────────────────────────────────────────────

setup_ttyd_source() {
    # Clone
    if [ ! -d "$TTYD_SRC/.git" ]; then
        echo "[*] Cloning ttyd source..."
        git clone --depth=1 https://github.com/tsl0922/ttyd "$TTYD_SRC"
        echo "[+] Cloned ttyd to $TTYD_SRC"
    else
        echo "[*] ttyd source already present — pulling latest..."
        git -C "$TTYD_SRC" pull --ff-only 2>/dev/null || \
            echo "[!] Pull skipped (uncommitted local changes or offline)"
    fi

    # cmake configure (validates deps, produces compile_commands.json for IDEs)
    local BUILD_DIR="$TTYD_SRC/build"
    mkdir -p "$BUILD_DIR"
    echo "[*] Running cmake configure..."
    (
        cd "$BUILD_DIR"
        # Use the real compiler here (not AFL++) — this is only for validation/headers
        cmake -DCMAKE_BUILD_TYPE=Debug \
              -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
              .. 2>&1 | tail -5 || true
    )
    echo "[+] cmake done (compile_commands.json at $BUILD_DIR/compile_commands.json)"

    # ── verify mock headers/sources exist ────────────────────────────────
    # These files are checked into the repo alongside the harnesses.
    # (Previously they were generated inline by this script.)
    for f in "$FUZZ_INCLUDE/libwebsockets.h" "$FUZZ_INCLUDE/uv.h" \
             "$SCRIPT_DIR/fuzz_lws_mock.h" "$SCRIPT_DIR/fuzz_lws_mock.c" \
             "$SCRIPT_DIR/mock_server_globals.c" "$SCRIPT_DIR/mock_pty_stubs.c"; do
        if [ ! -f "$f" ]; then
            echo "[!] Missing required file: $f"
            echo "    These files should be checked in alongside the harnesses."
            exit 1
        fi
    done
    echo "[+] Mock headers and stubs verified"

    # ── compile instrumented ttyd objects ────────────────────────────────
    mkdir -p "$TTYD_OBJ"
    local JSON_CFLAGS
    JSON_CFLAGS=$(pkg-config --cflags json-c 2>/dev/null || echo "")

    local OBJ_CC OBJ_CFLAGS
    if [ "$MODE" = "afl" ]; then
        OBJ_CC="afl-clang-fast"
    else
        OBJ_CC="clang"
    fi
    OBJ_CFLAGS="-fsanitize=$SANITIZER -g -O1 -D_GNU_SOURCE -std=gnu99"
    OBJ_CFLAGS="$OBJ_CFLAGS -I$FUZZ_INCLUDE -I$TTYD_SRC/src $JSON_CFLAGS"
    # Suppress warnings from upstream code we don't control
    OBJ_CFLAGS="$OBJ_CFLAGS -Wno-implicit-function-declaration -Wno-int-conversion"

    echo
    echo "[*] Compiling instrumented ttyd objects..."
    # Only utils.c is pre-compiled as a shared object.
    # http.c and protocol.c are compiled directly into each harness via
    # #include — pre-compiling them here would cause multiple-definition
    # linker errors.
    for src in utils; do
        echo "    $src.c → ttyd-obj/$src.o"
        $OBJ_CC $OBJ_CFLAGS -c "$TTYD_SRC/src/$src.c" -o "$TTYD_OBJ/$src.o"
    done

    # Mock objects
    for src in fuzz_lws_mock mock_server_globals mock_pty_stubs; do
        echo "    $src.c → ttyd-obj/$src.o"
        $OBJ_CC $OBJ_CFLAGS -c "$SCRIPT_DIR/$src.c" -o "$TTYD_OBJ/$src.o"
    done

    echo "[+] ttyd objects compiled to $TTYD_OBJ/"
}

# ─── 3. dictionaries ──────────────────────────────────────────────────────────

setup_dictionaries() {
    local DICT_DIR="$SCRIPT_DIR/dictionaries"
    mkdir -p "$DICT_DIR"

    # Try system AFL++ dictionaries first
    for sys_dir in /usr/share/afl++/dictionaries /usr/local/share/afl++/dictionaries; do
        if [ -d "$sys_dir" ]; then
            [ -f "$sys_dir/http.dict" ] && [ ! -f "$DICT_DIR/http.dict" ] && \
                cp "$sys_dir/http.dict" "$DICT_DIR/http.dict" && \
                echo "[+] Copied http.dict from $sys_dir"
            [ -f "$sys_dir/json.dict" ] && [ ! -f "$DICT_DIR/json.dict" ] && \
                cp "$sys_dir/json.dict" "$DICT_DIR/json.dict" && \
                echo "[+] Copied json.dict from $sys_dir"
            break
        fi
    done

    # Download from AFL++ GitHub if still missing (http.dict and json.dict
    # ship under those exact names in the AFL++ stable branch)
    local BASE="https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/dictionaries"
    local DL=""
    command -v wget  &>/dev/null && DL="wget -q -O"
    command -v curl  &>/dev/null && [ -z "$DL" ] && DL="curl -fsSL -o"

    for dict in http json; do
        if [ ! -f "$DICT_DIR/$dict.dict" ] && [ -n "$DL" ]; then
            echo "[*] Downloading $dict.dict from AFL++ repo..."
            $DL "$DICT_DIR/$dict.dict" "$BASE/$dict.dict" && \
                echo "[+] Downloaded $dict.dict" || \
                rm -f "$DICT_DIR/$dict.dict"
        fi
    done

    # Minimal fallback if still missing (from checked-in fallback files)
    if [ ! -f "$DICT_DIR/http.dict" ] && [ -f "$SCRIPT_DIR/dictionaries/http_fallback.dict" ]; then
        cp "$SCRIPT_DIR/dictionaries/http_fallback.dict" "$DICT_DIR/http.dict"
        echo "[+] Created dictionaries/http.dict (fallback)"
    fi

    if [ ! -f "$DICT_DIR/json.dict" ] && [ -f "$SCRIPT_DIR/dictionaries/json_fallback.dict" ]; then
        cp "$SCRIPT_DIR/dictionaries/json_fallback.dict" "$DICT_DIR/json.dict"
        echo "[+] Created dictionaries/json.dict (fallback)"
    fi

    echo "[+] Dictionaries: $(ls "$DICT_DIR")"
}

# ─── 4. corpus generation ─────────────────────────────────────────────────────

generate_corpus() {
    echo "[*] Running gen_corpus.py..."
    python3 "$SCRIPT_DIR/gen_corpus.py" "$SCRIPT_DIR"
}

# ─── 5. crash backup crontab ──────────────────────────────────────────────────

setup_crash_backup() {
    local BACKUP_DIR="$SCRIPT_DIR/crashes-backup"

    # Write the backup script from template
    sed -e "s|%%CRONTAB_MARKER%%|$CRONTAB_MARKER|g" \
        -e "s|%%SCRIPT_DIR%%|$SCRIPT_DIR|g" \
        -e "s|%%BACKUP_DIR%%|$BACKUP_DIR|g" \
        "$SCRIPT_DIR/backup_crashes.sh.in" > "$BACKUP_SCRIPT"
    chmod +x "$BACKUP_SCRIPT"
    echo "[+] Created $BACKUP_SCRIPT"

    # Install crontab entry (idempotent — remove stale entry first)
    local TMPFILE
    TMPFILE=$(mktemp)
    crontab -l 2>/dev/null | grep -v "$CRONTAB_MARKER" | grep -v "backup_crashes.sh" > "$TMPFILE" || true
    {
        cat "$TMPFILE"
        echo "$CRONTAB_MARKER"
        echo "*/15 * * * * $BACKUP_SCRIPT >> $SCRIPT_DIR/crashes-backup/backup.log 2>&1"
    } | crontab -
    rm -f "$TMPFILE"
    echo "[+] Crontab entry installed (every 15 min)"
    crontab -l | grep -A1 "$CRONTAB_MARKER"
}

# ─── 6. select compiler ───────────────────────────────────────────────────────

case "$MODE" in
    afl)
        if ! command -v afl-clang-fast &>/dev/null; then
            echo "[!] afl-clang-fast not found. Install AFL++ first."
            exit 1
        fi
        CC="afl-clang-fast"
        CFLAGS="-fsanitize=$SANITIZER -g -O1"
        SUFFIX=""
        ;;
    libfuzzer)
        if ! command -v clang &>/dev/null; then
            echo "[!] clang not found. Install clang first."
            exit 1
        fi
        CC="clang"
        CFLAGS="-fsanitize=fuzzer,$SANITIZER -g -O1"
        SUFFIX="_lf"
        ;;
    *)
        echo "[!] Unknown mode: $MODE  (use 'afl' or 'libfuzzer')"
        exit 1
        ;;
esac

# ─── find json-c ─────────────────────────────────────────────────────────────

JSON_C_CFLAGS=$(pkg-config --cflags json-c 2>/dev/null || echo "")
JSON_C_LIBS=$(pkg-config --libs   json-c 2>/dev/null || echo "-ljson-c")
if [ -z "$JSON_C_CFLAGS" ]; then
    for d in /usr/include /usr/local/include; do
        [ -f "$d/json-c/json.h" ] && JSON_C_CFLAGS="-I$d" && break
    done
fi
if [ -z "$JSON_C_CFLAGS" ]; then
    echo "[!] json-c headers not found. Run: sudo apt-get install libjson-c-dev"
    exit 1
fi

# ─── run setup stages ────────────────────────────────────────────────────────

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/7] Installing dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
install_deps

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2/7] Setting up ttyd source + instrumented objects"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
setup_ttyd_source

# ─── build harnesses ─────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/7] Building harnesses (with real ttyd code)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Common flags for all harnesses: our mock includes take priority over system
COMMON_CFLAGS="$CFLAGS -I$FUZZ_INCLUDE -I$TTYD_SRC/src $JSON_C_CFLAGS"
COMMON_CFLAGS="$COMMON_CFLAGS -Wno-implicit-function-declaration -Wno-int-conversion"

# http.c and protocol.c are compiled into each harness via #include — do NOT
# include their pre-compiled objects here or every symbol will be defined twice.
MOCK_OBJS="$TTYD_OBJ/utils.o"
MOCK_OBJS="$MOCK_OBJS $TTYD_OBJ/fuzz_lws_mock.o $TTYD_OBJ/mock_server_globals.o $TTYD_OBJ/mock_pty_stubs.o"

# http.c decompresses gzip-encoded HTML using zlib
EXTRA_LIBS="-lz"

echo "[*] Building fuzz_websocket_auth..."
$CC $COMMON_CFLAGS fuzz_websocket_auth.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS -o fuzz_websocket_auth$SUFFIX
echo "[+] Built: fuzz_websocket_auth$SUFFIX"

echo "[*] Building fuzz_http_parsing..."
$CC $COMMON_CFLAGS fuzz_http_parsing.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS -o fuzz_http_parsing$SUFFIX
echo "[+] Built: fuzz_http_parsing$SUFFIX"

# CmpLog variants (AFL++ only)
if [ "$MODE" = "afl" ]; then
    echo
    echo "[*] Building CmpLog variants..."
    AFL_LLVM_CMPLOG=1 $CC $COMMON_CFLAGS fuzz_websocket_auth.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS \
        -o fuzz_websocket_auth_cmplog
    echo "[+] Built: fuzz_websocket_auth_cmplog"
    AFL_LLVM_CMPLOG=1 $CC $COMMON_CFLAGS fuzz_http_parsing.c $MOCK_OBJS $JSON_C_LIBS $EXTRA_LIBS \
        -o fuzz_http_parsing_cmplog
    echo "[+] Built: fuzz_http_parsing_cmplog"

    echo
    echo "[*] Building HTTP custom mutator..."
    cc -shared -fPIC -O2 http_mutator.c -o http_mutator.so
    echo "[+] Built: http_mutator.so"
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[4/7] Setting up dictionaries"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
setup_dictionaries

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[5/7] Generating seed corpus"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
generate_corpus

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[6/7] Installing crash-backup crontab"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
setup_crash_backup

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[7/7] Done"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "Ready to fuzz:"
if [ "$MODE" = "afl" ]; then
    echo "  ./run-fuzzers.sh          # launch all targets in tmux"
    echo "  afl-fuzz -i corpus/websocket_auth -o output/websocket_auth -x dictionaries/json.dict ./fuzz_websocket_auth"
else
    echo "  ./fuzz_auth_header_lf corpus/auth_header/"
fi
echo
echo "Crashes backed up automatically every 15 min → crashes-backup/"
echo "To stop backup: ./clean.sh"
