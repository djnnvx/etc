#!/bin/bash
# Build script for TTYD authentication fuzzing harnesses

set -e

MODE="${1:-afl}"  # afl or libfuzzer
SANITIZER="address"

echo "[*] Building TTYD fuzzing harnesses"
echo "[*] Mode: $MODE"
echo "[*] Sanitizer: $SANITIZER"
echo

# Install dependencies if missing (requires root)
if [ "$(id -u)" -eq 0 ]; then
    DEPS_NEEDED=""
    dpkg -s libjson-c-dev &>/dev/null || DEPS_NEEDED="$DEPS_NEEDED libjson-c-dev"
    dpkg -s afl++ &>/dev/null || DEPS_NEEDED="$DEPS_NEEDED afl++"
    if [ -n "$DEPS_NEEDED" ]; then
        echo "[*] Installing missing dependencies:$DEPS_NEEDED"
        apt-get install -y $DEPS_NEEDED
        echo "[+] Dependencies installed"
        echo
    fi
fi

# System setup for AFL++ (requires root)
if [ "$MODE" == "afl" ] && [ "$(id -u)" -eq 0 ]; then
    echo "[*] Configuring system for AFL++..."

    # Fix core_pattern for crash detection
    CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern)
    if [[ "$CORE_PATTERN" == "|"* ]]; then
        echo "[*] Setting core_pattern to 'core'..."
        echo core > /proc/sys/kernel/core_pattern
        echo "[+] core_pattern set"
    else
        echo "[+] core_pattern already OK: $CORE_PATTERN"
    fi

    # Set CPU governor to performance
    if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
        CUR_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true)
        if [ "$CUR_GOV" != "performance" ]; then
            echo "[*] Setting CPU governor to performance (was: $CUR_GOV)..."
            for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                echo performance > "$gov" 2>/dev/null || true
            done
            echo "[+] CPU governor set"
        else
            echo "[+] CPU governor already set to performance"
        fi
    fi

    echo
elif [ "$MODE" == "afl" ] && [ "$(id -u)" -ne 0 ]; then
    echo "[!] Warning: Not running as root. System tuning skipped."
    echo "    Run with sudo for AFL++ system setup (core_pattern, CPU governor)."
    echo
fi

case "$MODE" in
    afl)
        echo "[*] Building with AFL++"

        # Check if AFL++ is installed
        if ! command -v afl-clang-fast &> /dev/null; then
            echo "[!] AFL++ not found. Please install AFL++:"
            echo "    sudo apt-get install afl++"
            echo "    Or: https://github.com/AFLplusplus/AFLplusplus"
            exit 1
        fi

        CC="afl-clang-fast"
        CFLAGS="-fsanitize=$SANITIZER -g -O1"
        SUFFIX=""

        echo "[+] Compiler: $CC"
        ;;

    libfuzzer)
        echo "[*] Building with LibFuzzer"

        # Check if clang is installed
        if ! command -v clang &> /dev/null; then
            echo "[!] Clang not found. Please install:"
            echo "    sudo apt-get install clang"
            exit 1
        fi

        CC="clang"
        CFLAGS="-fsanitize=fuzzer,$SANITIZER -g -O1"
        SUFFIX="_lf"

        echo "[+] Compiler: $CC"
        ;;

    *)
        echo "[!] Unknown mode: $MODE"
        echo "Usage: $0 [afl|libfuzzer]"
        exit 1
        ;;
esac

# Find json-c: try pkg-config first, then common paths
JSON_C_CFLAGS=$(pkg-config --cflags json-c 2>/dev/null || true)
JSON_C_LIBS=$(pkg-config --libs json-c 2>/dev/null || true)
if [ -z "$JSON_C_CFLAGS" ]; then
    for dir in /usr/include /usr/local/include; do
        if [ -f "$dir/json-c/json.h" ]; then
            JSON_C_CFLAGS="-I$dir"
            break
        fi
    done
fi
if [ -z "$JSON_C_LIBS" ]; then
    JSON_C_LIBS="-ljson-c"
fi
if [ -z "$JSON_C_CFLAGS" ]; then
    echo "[!] json-c headers not found. Install with: sudo apt-get install libjson-c-dev"
    exit 1
fi

# Build each harness
echo
echo "[*] Building fuzz_auth_header..."
$CC $CFLAGS fuzz_auth_header.c -o fuzz_auth_header$SUFFIX
echo "[+] Built: fuzz_auth_header$SUFFIX"

echo "[*] Building fuzz_websocket_auth..."
$CC $CFLAGS $JSON_C_CFLAGS fuzz_websocket_auth.c $JSON_C_LIBS -o fuzz_websocket_auth$SUFFIX
echo "[+] Built: fuzz_websocket_auth$SUFFIX"

echo "[*] Building fuzz_http_parsing..."
$CC $CFLAGS fuzz_http_parsing.c -o fuzz_http_parsing$SUFFIX
echo "[+] Built: fuzz_http_parsing$SUFFIX"

# Build CmpLog variants (AFL++ only)
if [ "$MODE" == "afl" ]; then
    echo
    echo "[*] Building CmpLog variants (for solving string comparisons)..."

    AFL_LLVM_CMPLOG=1 $CC $CFLAGS fuzz_auth_header.c -o fuzz_auth_header_cmplog
    echo "[+] Built: fuzz_auth_header_cmplog"

    AFL_LLVM_CMPLOG=1 $CC $CFLAGS $JSON_C_CFLAGS fuzz_websocket_auth.c $JSON_C_LIBS -o fuzz_websocket_auth_cmplog
    echo "[+] Built: fuzz_websocket_auth_cmplog"

    AFL_LLVM_CMPLOG=1 $CC $CFLAGS fuzz_http_parsing.c -o fuzz_http_parsing_cmplog
    echo "[+] Built: fuzz_http_parsing_cmplog"
fi

echo
echo "[+] All harnesses built successfully!"

# Generate corpus
echo
echo "[*] Generating seed corpus..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$SCRIPT_DIR/gen-corpus.sh"

echo
echo "[+] Ready to fuzz! Run:"
if [ "$MODE" == "afl" ]; then
    echo "   ./run_fuzzers.sh                # Launch all in tmux"
    echo "   # Or individually:"
    echo "   afl-fuzz -i corpus/auth_header -o output/auth_header ./fuzz_auth_header"
else
    echo "   ./fuzz_auth_header_lf corpus/auth_header"
fi
