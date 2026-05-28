#!/bin/bash
# setup.sh - bootstrap libnfs fuzzing environment.
# Same machine specs as the libksba/libusb harnesses: AFL++ (from source or
# system), CLASSIC+LAF instrumentation, a CmpLog sibling per harness, ASan+UBSan
# at -O0 -g. Signed-int-overflow and shift dropped from UBSan - they're noise
# in XDR codepaths that do `value = (value << 8) | next_byte`.
# Usage: bash setup.sh [--skip-deps] [--skip-afl]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

AFL_REPO="https://github.com/AFLplusplus/AFLplusplus.git"
AFL_BIN="${SCRIPT_DIR}/afl-build/usr/local/bin"

LIBNFS_REPO="${LIBNFS_REPO:-https://github.com/sahlberg/libnfs.git}"
LIBNFS_TAG="${LIBNFS_TAG:-master}"

# UBSan noise filters (lessons from libksba + smoke-testing libnfs):
#   signed-integer-overflow / shift  - XDR reads bytes into signed int and shifts
#   function                         - table-dispatch decoders use (fn_t)cast
#   alignment                        - zdr_u_int reads u32 at unaligned offset
# All four are benign on x86_64 in practice and would flood AFL with noise.
CFLAGS_FUZZ="-fsanitize=address,undefined -fno-sanitize=signed-integer-overflow,shift,function,alignment -g -O0 -fno-omit-frame-pointer"
CFLAGS_FUZZ+=" -Wno-implicit-function-declaration -Wno-unused-function -Wno-unused-variable"

HARNESSES="fuzz_nfs3 fuzz_nfs4 fuzz_mount fuzz_pdu"

SKIP_DEPS=0
SKIP_AFL=0
for arg in "$@"; do
    [[ "$arg" == "--skip-deps" ]] && SKIP_DEPS=1
    [[ "$arg" == "--skip-afl"  ]] && SKIP_AFL=1
done

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }
die() { echo "[!] $*" >&2; exit 1; }

if [[ "${SKIP_DEPS}" -eq 0 ]]; then
    log "Installing dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y \
        build-essential git tmux python3 \
        clang llvm lld pkg-config gdb cmake
    ok "Dependencies installed."
fi

if [[ "${SKIP_AFL}" -eq 1 ]]; then
    command -v afl-clang-fast > /dev/null 2>&1 || die "afl-clang-fast not found."
elif [[ -x "${AFL_BIN}/afl-clang-fast" ]]; then
    ok "AFL++ already built."
    export PATH="${AFL_BIN}:${PATH}"
else
    log "Building AFL++..."
    [[ -d "AFLplusplus" ]] || git clone --depth=1 "${AFL_REPO}" AFLplusplus
    ( cd AFLplusplus && make source-only -j"$(nproc)" \
        && make install PREFIX="${SCRIPT_DIR}/afl-build/usr/local" )
    export PATH="${AFL_BIN}:${PATH}"
    ok "AFL++ built."
fi
export PATH="${AFL_BIN}:${PATH}"

if [[ -d "libnfs-src/.git" ]]; then
    ok "libnfs-src present ($(cd libnfs-src && git describe --tags --always))."
else
    log "Cloning libnfs ${LIBNFS_TAG}..."
    git clone "${LIBNFS_REPO}" libnfs-src
    ( cd libnfs-src && git checkout -q "${LIBNFS_TAG}" )
    ok "libnfs-src cloned."
fi

# libnfs ships both autotools and CMake build systems. CMake is shorter to
# drive and produces a single libnfs.a (autotools fragments into one .la per
# protocol subdir + a libtoolize dance for shared-lib symbol export). We
# don't need shared libs, so CMake wins.
build_lib() {
    local dir="$1" cc="$2"; shift 2
    log "  building ${dir} (CC=${cc})..."
    rm -rf "${dir}"
    mkdir -p "${dir}"
    ( cd "${dir}" \
      && env "$@" CFLAGS="${CFLAGS_FUZZ}" \
            cmake -DCMAKE_C_COMPILER="${cc}" \
                  -DBUILD_SHARED_LIBS=OFF \
                  -DENABLE_UTILS=OFF \
                  -DENABLE_EXAMPLES=OFF \
                  -DENABLE_TESTS=OFF \
                  "${SCRIPT_DIR}/libnfs-src" >/dev/null \
      && env "$@" make -j"$(nproc)" >/dev/null )
    [[ -f "${dir}/lib/libnfs.a" ]] || die "${dir}: libnfs.a not produced"
}

log "Building libnfs: instrumented (CLASSIC+LAF), CmpLog, and a plain-ASan copy for repro..."
build_lib build-cls     afl-clang-fast AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_LAF_ALL=1
build_lib build-cmplog  afl-clang-fast AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_LAF_ALL=1 AFL_LLVM_CMPLOG=1
build_lib build-plain   clang
ok "libnfs built."

# CMake bundles everything into a single libnfs.a (protocol .o files are
# linked into the top-level static archive). -lpthread is the only runtime
# dep when krb5/gnutls are disabled.
COMMON_LDLIBS="-lpthread"

# Per-protocol headers live in their own subdirs (mount/, nfs/, nfs4/, ...).
# The harness #includes them by basename and we add each as -I.
HARNESS_INCS=(
    -I "${SCRIPT_DIR}/libnfs-src/include"
    -I "${SCRIPT_DIR}/libnfs-src/include/nfsc"
    -I "${SCRIPT_DIR}/libnfs-src/mount"
    -I "${SCRIPT_DIR}/libnfs-src/nfs"
    -I "${SCRIPT_DIR}/libnfs-src/nfs4"
    -I "${SCRIPT_DIR}/libnfs-src/portmap"
)

log "Building harnesses..."
for h in ${HARNESSES}; do
    log "  ${h}..."
    AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_LAF_ALL=1 \
        afl-clang-fast ${CFLAGS_FUZZ} "${HARNESS_INCS[@]}" \
            "${h}.c" "build-cls/lib/libnfs.a" ${COMMON_LDLIBS} -o "${h}"
    AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_LAF_ALL=1 AFL_LLVM_CMPLOG=1 \
        afl-clang-fast ${CFLAGS_FUZZ} "${HARNESS_INCS[@]}" \
            "${h}.c" "build-cmplog/lib/libnfs.a" ${COMMON_LDLIBS} -o "${h}.cmplog"
    clang ${CFLAGS_FUZZ} -DNFS_FUZZ_STANDALONE "${HARNESS_INCS[@]}" \
        "${h}.c" "build-plain/lib/libnfs.a" ${COMMON_LDLIBS} -o "${h}.repro"
done
ok "Harnesses built."

if [[ -d corpus/nfs3 && "$(ls corpus/nfs3 2>/dev/null | wc -l)" -gt 0 ]]; then
    ok "Corpus present."
else
    log "Generating corpus..."
    bash gen_corpus.sh
fi

ok "Done. Run: bash start-fuzzers.sh"
