#!/bin/bash
# setup.sh - bootstrap libksba fuzzing environment.
# Same machine specs as the libusb harness: AFL++ from source, CLASSIC+LAF
# instrumentation, a CmpLog sibling per harness, ASan+UBSan+signed-overflow at -O0 -g.
# Usage: bash setup.sh [--skip-deps] [--skip-afl]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

AFL_REPO="https://github.com/AFLplusplus/AFLplusplus.git"
AFL_BIN="${SCRIPT_DIR}/afl-build/usr/local/bin"

# libksba defaults to git tip (1.8.x, reportable upstream now). For the line
# dirmngr/gpgsm actually link against in distros, set LIBKSBA_TAG=libksba-1.6.6.
LIBKSBA_REPO="${LIBKSBA_REPO:-https://github.com/gpg/libksba.git}"
LIBKSBA_TAG="${LIBKSBA_TAG:-master}"

CFLAGS_FUZZ="-fsanitize=address,undefined,signed-integer-overflow -g -O0 -fno-omit-frame-pointer"
CFLAGS_FUZZ+=" -Wno-implicit-function-declaration -Wno-unused-function -Wno-unused-variable"

HARNESSES="fuzz_cert fuzz_crl fuzz_ocsp fuzz_cms"

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
        clang llvm lld pkg-config gdb \
        autoconf automake libtool gettext bison texinfo \
        libgpg-error-dev openssl
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

if [[ -d "libksba-src/.git" ]]; then
    ok "libksba-src present ($(cd libksba-src && git describe --tags --always))."
else
    log "Cloning libksba ${LIBKSBA_TAG}..."
    git clone "${LIBKSBA_REPO}" libksba-src
    ( cd libksba-src && git checkout -q "${LIBKSBA_TAG}" )
    ok "libksba-src cloned."
fi

[[ -x libksba-src/configure ]] || ( cd libksba-src && ./autogen.sh >/dev/null 2>&1 )

# Out-of-tree builds keep the CLASSIC/CmpLog/plain object sets separate. Build gl
# then just libksba.la: the rest of src (ber-dump, tests) needs more deps.
build_lib() {
    local dir="$1" cc="$2"; shift 2
    log "  building ${dir} (CC=${cc})..."
    rm -rf "${dir}"
    mkdir -p "${dir}"
    ( cd "${dir}" \
      && env "$@" "${SCRIPT_DIR}/libksba-src/configure" \
            CC="${cc}" CFLAGS="${CFLAGS_FUZZ}" \
            --enable-static --disable-shared --disable-maintainer-mode >/dev/null \
      && env "$@" make -C gl  -j"$(nproc)" >/dev/null \
      && env "$@" make -C src libksba.la -j"$(nproc)" >/dev/null )
    [[ -f "${dir}/src/.libs/libksba.a" ]] || die "${dir}: libksba.a not produced"
}

log "Building libksba: instrumented (CLASSIC+LAF), CmpLog, and a plain-ASan copy for repro..."
build_lib build-cls     afl-clang-fast AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_LAF_ALL=1
build_lib build-cmplog  afl-clang-fast AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_LAF_ALL=1 AFL_LLVM_CMPLOG=1
build_lib build-plain   clang
ok "libksba built."

GPGERR_CFLAGS="$(gpg-error-config --cflags 2>/dev/null || pkg-config --cflags gpg-error 2>/dev/null || true)"
GPGERR_LIBS="$(gpg-error-config --libs 2>/dev/null || pkg-config --libs gpg-error 2>/dev/null || echo -lgpg-error)"

# gnulib convenience archive libksba links against; omit gracefully if absent.
gnulib() { local a="$1/gl/.libs/libgnu.a"; [[ -f "$a" ]] && echo "$a"; }
CLS_LIBS="build-cls/src/.libs/libksba.a $(gnulib build-cls)"
CMP_LIBS="build-cmplog/src/.libs/libksba.a $(gnulib build-cmplog)"
PLAIN_LIBS="build-plain/src/.libs/libksba.a $(gnulib build-plain)"

# harnesses: AFL persistent, CmpLog sibling, and a plain-clang ASan repro binary.
log "Building harnesses..."
for h in ${HARNESSES}; do
    log "  ${h}..."
    AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_LAF_ALL=1 \
        afl-clang-fast ${CFLAGS_FUZZ} -I build-cls/src -I libksba-src/src ${GPGERR_CFLAGS} \
        "${h}.c" ${CLS_LIBS} ${GPGERR_LIBS} -o "${h}"
    AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_LAF_ALL=1 AFL_LLVM_CMPLOG=1 \
        afl-clang-fast ${CFLAGS_FUZZ} -I build-cmplog/src -I libksba-src/src ${GPGERR_CFLAGS} \
        "${h}.c" ${CMP_LIBS} ${GPGERR_LIBS} -o "${h}.cmplog"
    clang ${CFLAGS_FUZZ} -DKSBA_FUZZ_STANDALONE -I build-plain/src -I libksba-src/src ${GPGERR_CFLAGS} \
        "${h}.c" ${PLAIN_LIBS} ${GPGERR_LIBS} -o "${h}.repro"
done
ok "Harnesses built."

if [[ -d corpus/cert && "$(ls corpus/cert 2>/dev/null | wc -l)" -gt 0 ]]; then
    ok "Corpus present."
else
    log "Generating corpus..."
    bash gen_corpus.sh
fi

ok "Done. Run: bash start-fuzzers.sh"
