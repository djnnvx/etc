#!/bin/bash
# build_fuzzers.sh — compile AFL++ in-process fuzzing harnesses.
#
# Assumes setup.sh has already run and usbip-src/ exists.
# Can be run standalone after the initial setup to iterate on harnesses.
#
# Outputs: fuzz_protocol, fuzz_devlist, fuzz_urb
#          + *.cmplog variants for AFL++ CmpLog mode
#
# Usage:
#   bash build_fuzzers.sh
#   bash build_fuzzers.sh --clean   # remove all binaries before rebuilding

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

# Add AFL++ to PATH if installed locally by setup.sh
AFL_BIN="${SCRIPT_DIR}/afl-build/usr/local/bin"
[[ -d "${AFL_BIN}" ]] && export PATH="${AFL_BIN}:${PATH}"

CC="afl-clang-fast"
USBIP_SRC="${SCRIPT_DIR}/usbip-src/src"
USBIP_LIB="${SCRIPT_DIR}/usbip-src/libsrc"

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
die()  { echo "[!] $*" >&2; exit 1; }

if [[ "${1:-}" == "--clean" ]]; then
    log "Cleaning build artifacts..."
    rm -f fuzz_protocol fuzz_devlist fuzz_urb fuzz_stub_client
    rm -f fuzz_protocol.cmplog fuzz_devlist.cmplog fuzz_urb.cmplog
    rm -f usbip_network.o usbip_common.o mock_syscalls.o names.o
    ok "Clean done."
fi

# ── sanity checks ─────────────────────────────────────────────────────────────
command -v "${CC}" > /dev/null 2>&1 \
    || die "afl-clang-fast not found. Run setup.sh first (or add AFL++ to PATH)."

[[ -d "${USBIP_SRC}" ]] \
    || die "usbip-src/src not found. Run setup.sh first."

# ── ensure corpus and dict exist ─────────────────────────────────────────────
[[ -d "corpus" ]] || python3 gen_corpus.py

# ── common compiler flags ─────────────────────────────────────────────────────
CFLAGS="-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer"
CFLAGS+=" -I fuzz-include"
CFLAGS+=" -I ${SCRIPT_DIR}/usbip-src"   # for config.h (HAVE_CONFIG_H / USBIP_VERSION)
CFLAGS+=" -I ${USBIP_SRC}"
CFLAGS+=" -I ${USBIP_LIB}"
CFLAGS+=" -Wno-implicit-function-declaration"
CFLAGS+=" -Wno-int-conversion"
CFLAGS+=" -Wno-pointer-to-int-cast"
CFLAGS+=" -Wno-incompatible-pointer-types"
CFLAGS+=" -DFUZZ_BUILD -DHAVE_CONFIG_H"

# glib-2.0 is needed by usbip_common.c
GLIB_CFLAGS="$(pkg-config --cflags glib-2.0 2>/dev/null || echo '')"
GLIB_LIBS="$(pkg-config --libs glib-2.0 2>/dev/null || echo '-lglib-2.0')"
CFLAGS+=" ${GLIB_CFLAGS}"

LDFLAGS="-Wl,--wrap=recv -Wl,--wrap=send -Wl,--wrap=write"
LDFLAGS+=" -ludev"
LDFLAGS+=" ${GLIB_LIBS}"

# ── Step 1: compile shared usbip objects ─────────────────────────────────────
log "Compiling usbip_network.o..."
${CC} ${CFLAGS} -c "${USBIP_SRC}/usbip_network.c" -o usbip_network.o

log "Compiling usbip_common.o..."
${CC} ${CFLAGS} -c "${USBIP_LIB}/usbip_common.c" -o usbip_common.o 2>/dev/null || \
    ${CC} ${CFLAGS} -c "${USBIP_SRC}/usbip_common.c" -o usbip_common.o

log "Compiling mock_syscalls.o..."
${CC} ${CFLAGS} -c mock_syscalls.c -o mock_syscalls.o

log "Compiling names.o..."
${CC} ${CFLAGS} -c "${USBIP_LIB}/names.c" -o names.o

COMMON_OBJS="usbip_network.o usbip_common.o mock_syscalls.o names.o"

# ── Step 2: build each in-process harness (standard + CmpLog) ────────────────

build_harness() {
    local name="$1"
    local src="$2"

    log "Building ${name}..."
    ${CC} ${CFLAGS} ${src} ${COMMON_OBJS} ${LDFLAGS} -o "${name}"

    log "Building ${name}.cmplog (CmpLog variant)..."
    AFL_LLVM_CMPLOG=1 ${CC} ${CFLAGS} ${src} ${COMMON_OBJS} ${LDFLAGS} -o "${name}.cmplog"

    ok "  ${name}  ${name}.cmplog"
}

build_harness fuzz_protocol fuzz_protocol.c
build_harness fuzz_devlist  fuzz_devlist.c
build_harness fuzz_urb      fuzz_urb.c

# fuzz_stub_client: malicious USB-IP client targeting usbipd stub_rx.c
# No ASAN / usbip library linkage — connects over TCP to the QEMU VM.
if [[ ! -f "fuzz_stub_client" ]] || [[ "fuzz_stub_client.c" -nt "fuzz_stub_client" ]]; then
    log "Building fuzz_stub_client (malicious client targeting stub_rx.c)..."
    ${CC} -O2 -o fuzz_stub_client fuzz_stub_client.c
    ok "  fuzz_stub_client"
fi

# ── Step 3: build QEMU-mode network tools ─────────────────────────────────────
# net_send: blind TCP relay (original QEMU mode — server side)
if [[ ! -f "net_send" ]] || [[ "net_send.c" -nt "net_send" ]]; then
    log "Building net_send (blind TCP relay for QEMU server-side mode)..."
    ${CC} -O2 -o net_send net_send.c
    ok "  net_send"
fi

# fuzz_vhci_server: two-sided fuzzer targeting vhci-hcd in QEMU client mode
if [[ ! -f "fuzz_vhci_server" ]] || [[ "fuzz_vhci_server.c" -nt "fuzz_vhci_server" ]]; then
    log "Building fuzz_vhci_server (two-sided server targeting vhci-hcd)..."
    ${CC} -O2 -o fuzz_vhci_server fuzz_vhci_server.c
    ok "  fuzz_vhci_server"
fi

# ── Step 4: build KCOV shim (for kernel coverage feedback) ───────────────────
# kcov_shim runs INSIDE the QEMU VM. Cross-compile or build on the guest.
# Here we build a host-native version for testing; deploy to VM initramfs manually.
if [[ ! -f "kcov_shim" ]] || [[ "kcov_shim.c" -nt "kcov_shim" ]]; then
    log "Building kcov_shim (KCOV coverage shim — deploy inside QEMU VM)..."
    gcc -O2 -static -o kcov_shim kcov_shim.c 2>/dev/null || \
        gcc -O2 -o kcov_shim kcov_shim.c && \
        ok "  kcov_shim (dynamic — static build failed, ensure libc is in VM)" || \
        echo "[!] kcov_shim build failed (needs kernel KCOV headers) — skip for now"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
ok "All harnesses built:"
ls -lh fuzz_protocol fuzz_devlist fuzz_urb fuzz_vhci_server fuzz_stub_client 2>/dev/null
echo ""
echo "  Quick smoke test:"
echo "    ./fuzz_protocol corpus/op_common_req_devlist"
echo "    ./fuzz_urb      corpus/urb_submit_64b"
echo ""
echo "  In-process (no VM):    bash run-fuzzers.sh"
echo "  QEMU vhci (two-sided): afl-fuzz -S vhci  -i corpus/vhci -o output -t 5000 -- ./fuzz_vhci_server @@ 0.0.0.0 13241"
echo "  QEMU stub (client):    afl-fuzz -S stub  -i corpus/stub -o output -t 5000 -- ./fuzz_stub_client @@ <vm-ip> 3240"
