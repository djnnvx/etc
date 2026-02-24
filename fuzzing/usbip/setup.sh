#!/bin/bash
# setup.sh — one-shot bootstrap for the usbipd fuzzing environment.
#
# What this does (in order):
#   1. Install system dependencies
#   2. Clone + build AFL++ with QEMU mode
#   3. Download + configure + build minimal Linux 6.12 LTS kernel
#   4. Build static busybox
#   5. Build usbipd from kernel tools (instrumented for AFL++, and plain for initramfs)
#   6. Assemble initramfs (busybox + usbipd + /init)
#   7. Compile net_send.c
#
# Re-running is safe: each step checks for existing artifacts and skips.
# Override KERNEL_VER or BUSYBOX_VER env vars to use different versions.
#
# Usage:
#   bash setup.sh
#   bash setup.sh --no-kernel   # skip kernel build (use existing bzImage)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

KERNEL_VER="${KERNEL_VER:-6.12}"
BUSYBOX_VER="${BUSYBOX_VER:-1.36.1}"
AFL_REPO="https://github.com/AFLplusplus/AFLplusplus.git"

SKIP_KERNEL=0
for arg in "$@"; do
    [[ "$arg" == "--no-kernel" ]] && SKIP_KERNEL=1
done

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
warn() { echo "[!] $*"; }

# ── 1. System dependencies ───────────────────────────────────────────────────
log "Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y \
    build-essential git curl wget python3 python3-pip tmux \
    libelf-dev libssl-dev flex bison bc cpio \
    libncurses-dev libncurses5-dev \
    libusb-1.0-0-dev libudev-dev libglib2.0-dev \
    pkg-config autoconf automake libtool \
    qemu-system-x86 \
    gcc-multilib \
    llvm clang lld \
    gdb
ok "Dependencies installed."

# ── 2. AFL++ ─────────────────────────────────────────────────────────────────
if [[ ! -x "afl-build/usr/local/bin/afl-fuzz" ]]; then
    log "Cloning AFL++..."
    [[ -d "AFLplusplus" ]] || git clone --depth=1 "${AFL_REPO}" AFLplusplus

    log "Building AFL++ (distrib target — includes QEMU mode)..."
    cd AFLplusplus

    # QEMU mode requires python3-dev
    sudo apt-get install -y python3-dev python3-setuptools

    # make distrib builds: core + LLVM instrumentation + QEMU mode
    make distrib -j"$(nproc)"

    # Install into local prefix so we don't pollute /usr/local
    make install PREFIX="${SCRIPT_DIR}/afl-build/usr/local"
    cd "${SCRIPT_DIR}"
    ok "AFL++ built."
else
    ok "AFL++ already built, skipping."
fi

# Add AFL++ to PATH for this session and child processes
export PATH="${SCRIPT_DIR}/afl-build/usr/local/bin:${PATH}"

# ── 3. Linux kernel ──────────────────────────────────────────────────────────
KERNEL_DIR="linux-${KERNEL_VER}"
KERNEL_TAR="linux-${KERNEL_VER}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TAR}"

if [[ "${SKIP_KERNEL}" -eq 1 ]]; then
    warn "--no-kernel: skipping kernel build."
elif [[ -f "bzImage" ]]; then
    ok "bzImage already exists, skipping kernel build."
else
    if [[ ! -d "${KERNEL_DIR}" ]]; then
        log "Downloading Linux ${KERNEL_VER}..."
        wget -q --show-progress -c "${KERNEL_URL}"
        log "Extracting..."
        tar -xf "${KERNEL_TAR}"
        rm -f "${KERNEL_TAR}"
    fi

    log "Configuring kernel (allnoconfig + USB/IP fragment)..."
    cd "${KERNEL_DIR}"

    make allnoconfig

    # Merge our minimal USB/IP config on top of allnoconfig
    scripts/kconfig/merge_config.sh -m .config "${SCRIPT_DIR}/qemu/kernel.config"

    # Resolve any unresolved dependencies automatically
    make olddefconfig

    log "Building kernel (this takes ~15-20 min on first run)..."
    make -j"$(nproc)" bzImage 2>&1 | tail -5

    cp arch/x86/boot/bzImage "${SCRIPT_DIR}/bzImage"
    cd "${SCRIPT_DIR}"
    ok "Kernel built: bzImage"
fi

# ── 4. Busybox (static) ──────────────────────────────────────────────────────
BUSYBOX_DIR="busybox-${BUSYBOX_VER}"
BUSYBOX_TAR="${BUSYBOX_DIR}.tar.bz2"
BUSYBOX_URL="https://busybox.net/downloads/${BUSYBOX_TAR}"

if [[ -d "busybox-install" ]]; then
    ok "Busybox already built, skipping."
else
    if [[ ! -d "${BUSYBOX_DIR}" ]]; then
        log "Downloading busybox ${BUSYBOX_VER}..."
        wget -q --show-progress -c "${BUSYBOX_URL}"
        tar -xjf "${BUSYBOX_TAR}"
        rm -f "${BUSYBOX_TAR}"
    fi

    log "Building static busybox..."
    cd "${BUSYBOX_DIR}"
    make defconfig
    # Enable static build
    sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
    sed -i 's/CONFIG_STATIC=n/CONFIG_STATIC=y/' .config
    echo "CONFIG_STATIC=y" >> .config
    make oldconfig < /dev/null || true
    make -j"$(nproc)"
    make install CONFIG_PREFIX="${SCRIPT_DIR}/busybox-install"
    cd "${SCRIPT_DIR}"
    ok "Busybox installed to busybox-install/"
fi

# ── 5. usbip userspace tools ─────────────────────────────────────────────────
USBIP_SRC="${SCRIPT_DIR}/usbip-src"

if [[ "${SKIP_KERNEL}" -eq 0 ]] && [[ -d "${SCRIPT_DIR}/${KERNEL_DIR}" ]]; then
    KERNEL_USBIP="${SCRIPT_DIR}/${KERNEL_DIR}/tools/usb/usbip"
else
    warn "No kernel source directory found. Skipping usbip build."
    KERNEL_USBIP=""
fi

if [[ -n "${KERNEL_USBIP}" ]]; then
    # 5a. Plain build (for initramfs — not AFL instrumented)
    if [[ ! -f "usbipd-plain" ]]; then
        log "Building usbipd (plain, for initramfs)..."
        cd "${KERNEL_USBIP}"
        ./autogen.sh
        ./configure --prefix="${SCRIPT_DIR}/usbipd-plain-install" \
                    LDFLAGS="-static" \
                    CFLAGS="-O2 -g"
        make -j"$(nproc)"
        make install
        cd "${SCRIPT_DIR}"
        cp usbipd-plain-install/sbin/usbipd usbipd-plain || \
            cp usbipd-plain-install/usr/sbin/usbipd usbipd-plain 2>/dev/null || true
        ok "Plain usbipd built."
    fi

    # 5b. AFL++-instrumented copy of the source (for in-process harnesses)
    if [[ ! -d "${USBIP_SRC}" ]]; then
        log "Copying usbip source for AFL++ instrumented build..."
        cp -r "${KERNEL_USBIP}" "${USBIP_SRC}"
    fi

    ok "usbip source available at ${USBIP_SRC}/"
fi

# ── 6. Initramfs ──────────────────────────────────────────────────────────────
if [[ -f "initramfs.cpio.gz" ]]; then
    ok "initramfs.cpio.gz already exists, skipping."
else
    log "Assembling initramfs..."
    rm -rf initramfs
    mkdir -p initramfs/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,tmp,run,lib,lib64,etc}

    # Busybox
    cp busybox-install/bin/busybox initramfs/bin/busybox
    # Install all busybox applets as symlinks
    (cd initramfs && bin/busybox --list | while read applet; do
        ln -sf /bin/busybox bin/"${applet}" 2>/dev/null || true
    done)
    # Ensure sh and ip are present
    ln -sf /bin/busybox initramfs/bin/sh
    ln -sf /bin/busybox initramfs/sbin/ip
    ln -sf /bin/busybox initramfs/sbin/modprobe

    # usbipd binary
    if [[ -f "usbipd-plain" ]]; then
        cp usbipd-plain initramfs/usr/sbin/usbipd
    else
        warn "usbipd-plain not found — initramfs will have no daemon!"
        warn "Run setup.sh after kernel source is available."
        # Create a placeholder so the initramfs structure is correct
        echo '#!/bin/sh
echo "usbipd not found"
exit 1' > initramfs/usr/sbin/usbipd
    fi
    chmod +x initramfs/usr/sbin/usbipd

    # If usbipd is dynamic, bundle its shared libraries
    if [[ -f "usbipd-plain" ]] && file usbipd-plain | grep -q "dynamically linked"; then
        log "Bundling shared libraries for dynamic usbipd..."
        ldd usbipd-plain | grep -oP '(/[^ ]+\.so[^ ]*)' | while read lib; do
            [[ -f "$lib" ]] || continue
            libdir="initramfs/$(dirname "${lib#/}")"
            mkdir -p "${libdir}"
            cp "${lib}" "${libdir}/"
        done
        # Copy the dynamic linker
        for ld in /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do
            [[ -f "$ld" ]] && cp "$ld" initramfs/lib64/ld-linux-x86-64.so.2 && break
        done
    fi

    # /init script
    cp qemu/init initramfs/init
    chmod +x initramfs/init

    log "Packing initramfs..."
    (cd initramfs && find . | cpio -oH newc 2>/dev/null | gzip -9) > initramfs.cpio.gz
    ok "initramfs.cpio.gz: $(du -sh initramfs.cpio.gz | cut -f1)"
fi

# ── 7. net_send.c ─────────────────────────────────────────────────────────────
if [[ ! -f "net_send" ]]; then
    log "Compiling net_send.c..."
    gcc -O2 -Wall -o net_send net_send.c
    ok "net_send compiled."
fi

# ── 8. Generate corpus ────────────────────────────────────────────────────────
if [[ ! -d "corpus" ]]; then
    log "Generating seed corpus..."
    python3 gen_corpus.py
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
ok "Setup complete. Next steps:"
echo "  1. Build harnesses:  bash build_fuzzers.sh"
echo "  2. Start fuzzing:    bash run-fuzzers.sh"
echo "  3. Verify QEMU:      qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio.gz \\"
echo "                         -nographic -append 'console=ttyS0 quiet' -m 64M"
echo "                       Then: nc 127.0.0.1 13240  (should get a response from usbipd)"
