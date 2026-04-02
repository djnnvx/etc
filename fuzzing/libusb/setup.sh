#!/bin/bash
# setup.sh — bootstrap libusb fuzzing environment.
# Usage: bash setup.sh [--skip-deps] [--skip-afl]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

AFL_REPO="https://github.com/AFLplusplus/AFLplusplus.git"
LIBUSB_TAG="v1.0.29"
LIBUSB_REPO="https://github.com/libusb/libusb.git"
AFL_BIN="${SCRIPT_DIR}/afl-build/usr/local/bin"

SKIP_DEPS=0
SKIP_AFL=0
for arg in "$@"; do
    [[ "$arg" == "--skip-deps" ]] && SKIP_DEPS=1
    [[ "$arg" == "--skip-afl"  ]] && SKIP_AFL=1
done

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }
die() { echo "[!] $*" >&2; exit 1; }

# deps
if [[ "${SKIP_DEPS}" -eq 0 ]]; then
    log "Installing dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y \
        build-essential git tmux python3 \
        clang llvm lld pkg-config gdb
    ok "Dependencies installed."
fi

# AFL++
if [[ "${SKIP_AFL}" -eq 1 ]]; then
    command -v afl-clang-fast > /dev/null 2>&1 || die "afl-clang-fast not found."
elif [[ -x "${AFL_BIN}/afl-clang-fast" ]]; then
    ok "AFL++ already built."
    export PATH="${AFL_BIN}:${PATH}"
else
    log "Building AFL++..."
    [[ -d "AFLplusplus" ]] || git clone --depth=1 "${AFL_REPO}" AFLplusplus
    cd AFLplusplus
    make source-only -j"$(nproc)"
    make install PREFIX="${SCRIPT_DIR}/afl-build/usr/local"
    cd "${SCRIPT_DIR}"
    export PATH="${AFL_BIN}:${PATH}"
    ok "AFL++ built."
fi

# libusb source
if [[ -d "libusb-src/.git" ]]; then
    ok "libusb-src present."
else
    log "Cloning libusb ${LIBUSB_TAG}..."
    git clone --depth=1 --branch "${LIBUSB_TAG}" "${LIBUSB_REPO}" libusb-src
    ok "libusb-src cloned."
fi

# build harnesses
log "Building harnesses..."
CC="afl-clang-fast"
SRC="libusb-src/libusb"
CFLAGS="-fsanitize=address,undefined,signed-integer-overflow -g -O0 -fno-omit-frame-pointer"
CFLAGS+=" -I fuzz-include -I ${SRC} -DFUZZ_BUILD"
CFLAGS+=" -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-unused-function -Wno-unused-variable"

build() {
    local name="$1" extra_src="${2:-}" extra_flags="${3:-}"
    log "  ${name}..."
    AFL_LLVM_LAF_ALL=1 AFL_LLVM_INSTRUMENT=CLASSIC ${CC} ${CFLAGS} ${extra_flags} "${name}.c" fuzz_stubs.c ${extra_src} -o "${name}" -lpthread
    AFL_LLVM_LAF_ALL=1 AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_CMPLOG=1 ${CC} ${CFLAGS} ${extra_flags} "${name}.c" fuzz_stubs.c ${extra_src} -o "${name}.cmplog" -lpthread
}

build fuzz_descriptor
build fuzz_bos
build fuzz_iad
build fuzz_usbfs "fuzz_usbfs_shim.c" "-I ${SRC}/os"
build fuzz_extra
ok "Harnesses built."

# corpus
if [[ -d "corpus/descriptor" && "$(ls corpus/descriptor | wc -l)" -gt 5 ]]; then
    ok "Corpus present."
else
    log "Generating corpus..."
    python3 gen_corpus.py
fi

ok "Done. Run: bash run-all.sh"
