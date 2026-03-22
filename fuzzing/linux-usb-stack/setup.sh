#!/bin/bash
# setup.sh — one-shot bootstrap for the linux-usb-stack syzkaller fuzzing environment.
#
# What this does (in order):
#   1. Install system dependencies
#   2. Install Go (from upstream if system Go < 1.21)
#   3. Clone + build syzkaller
#   4. Download + configure + build Linux mainline kernel
#   5. Build static busybox
#   6. Build static dropbear (SSH server for syzkaller VM access)
#   7. Generate SSH key pair for syzkaller ↔ VM communication
#   8. Assemble initramfs (busybox + dropbear + authorized_keys + /init)
#   9. Create workdirs for each fuzzing profile
#
# Re-running is safe: each step checks for existing artifacts and skips.
#
# Usage:
#   bash setup.sh
#   bash setup.sh --no-kernel      # skip kernel build (use existing bzImage)
#   bash setup.sh --no-syzkaller   # skip syzkaller build
#   bash setup.sh --skip-deps      # skip apt-get installs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

BUSYBOX_VER="${BUSYBOX_VER:-1.36.1}"
DROPBEAR_VER="${DROPBEAR_VER:-2024.86}"
GO_MIN_VER="1.21"
GO_INSTALL_VER="${GO_INSTALL_VER:-1.22.4}"  # upstream Go version to install if needed
SYZKALLER_REPO="https://github.com/google/syzkaller"
LINUX_REPO="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"

SKIP_KERNEL=0
SKIP_SYZKALLER=0
SKIP_DEPS=0
for arg in "$@"; do
    [[ "${arg}" == "--no-kernel"    ]] && SKIP_KERNEL=1
    [[ "${arg}" == "--no-syzkaller" ]] && SKIP_SYZKALLER=1
    [[ "${arg}" == "--skip-deps"    ]] && SKIP_DEPS=1
done

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
warn() { echo "[!] $*"; }

# ── 1. System dependencies ───────────────────────────────────────────────────
if [[ "${SKIP_DEPS}" -eq 1 ]]; then
    ok "Skipping dependency install (--skip-deps)."
else
    log "Installing system dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y \
        build-essential git curl wget python3 python3-pip tmux \
        libelf-dev libssl-dev flex bison bc cpio \
        libncurses-dev libncurses5-dev \
        pkg-config autoconf automake libtool \
        qemu-system-x86 \
        gcc-multilib \
        openssh-client \
        zlib1g-dev \
        gdb
    ok "System dependencies installed."
fi

# ── 2. Go ────────────────────────────────────────────────────────────────────
# syzkaller requires Go >= 1.21. Check system Go; install upstream if too old.
GO_BIN=""
for cand in "$(go env GOROOT 2>/dev/null)/bin/go" "${SCRIPT_DIR}/go/bin/go" /usr/local/go/bin/go; do
    if [[ -x "${cand}" ]]; then
        ver="$("${cand}" version | awk '{print $3}' | sed 's/go//')"
        major="${ver%%.*}"
        minor="${ver#*.}"; minor="${minor%%.*}"
        req_minor="${GO_MIN_VER#*.}"
        if [[ "${major}" -gt 1 ]] || [[ "${major}" -eq 1 && "${minor}" -ge "${req_minor}" ]]; then
            GO_BIN="${cand}"
            break
        fi
    fi
done

if [[ -z "${GO_BIN}" ]]; then
    log "Go >= ${GO_MIN_VER} not found. Installing Go ${GO_INSTALL_VER} from upstream..."
    GO_ARCHIVE="go${GO_INSTALL_VER}.linux-amd64.tar.gz"
    GO_URL="https://golang.org/dl/${GO_ARCHIVE}"
    wget -c --timeout=60 --tries=3 "${GO_URL}" -O "${GO_ARCHIVE}"
    tar -C "${SCRIPT_DIR}" -xzf "${GO_ARCHIVE}"
    rm -f "${GO_ARCHIVE}"
    GO_BIN="${SCRIPT_DIR}/go/bin/go"
    ok "Go ${GO_INSTALL_VER} installed to ${SCRIPT_DIR}/go/"
else
    ok "Go found: ${GO_BIN} ($(${GO_BIN} version | awk '{print $3}'))"
fi

export PATH="$(dirname "${GO_BIN}"):${PATH}"
export GOPATH="${SCRIPT_DIR}/gopath"
export GOROOT="$(dirname "$(dirname "${GO_BIN}")")"

# ── 3. syzkaller ─────────────────────────────────────────────────────────────
if [[ "${SKIP_SYZKALLER}" -eq 1 ]]; then
    ok "Skipping syzkaller build (--no-syzkaller)."
elif [[ -x "${SCRIPT_DIR}/syzkaller/bin/linux_amd64/syz-manager" ]]; then
    ok "syzkaller already built, skipping."
else
    log "Cloning syzkaller..."
    [[ -d "syzkaller" ]] || git clone --depth=1 "${SYZKALLER_REPO}" syzkaller

    log "Building syzkaller (this takes a few minutes)..."
    cd syzkaller
    make all -j"$(nproc)" 2>&1 | tail -5
    cd "${SCRIPT_DIR}"
    SYZ_MANAGER="$(find syzkaller/bin -name "syz-manager" -type f 2>/dev/null | head -1)"
    [[ -n "${SYZ_MANAGER}" ]] || { warn "syz-manager not found after build. Check build output above."; exit 1; }
    ok "syzkaller built: ${SYZ_MANAGER}"
fi

# ── 4. Linux kernel (mainline) ───────────────────────────────────────────────
if [[ "${SKIP_KERNEL}" -eq 1 ]]; then
    warn "--no-kernel: skipping kernel build."
elif [[ -f "bzImage" ]]; then
    ok "bzImage already exists, skipping kernel build."
else
    if [[ ! -d "linux" ]]; then
        log "Cloning Linux mainline (shallow — latest tag only)..."
        git clone --depth=1 "${LINUX_REPO}" linux
    fi

    log "Configuring kernel (allnoconfig + USB stack fragment)..."
    cd linux

    # GCC 15+ defaults to C23, where 'bool'/'false' are keywords — patch compressed/Makefile
    if gcc --version 2>&1 | grep -qE "gcc \(.*\) (1[5-9]|[2-9][0-9])\."; then
        sed -i 's/^KBUILD_CFLAGS := /KBUILD_CFLAGS := -std=gnu11 /' \
            arch/x86/boot/compressed/Makefile
        warn "GCC 15+ detected: patched compressed/Makefile with -std=gnu11"
    fi

    make allnoconfig
    scripts/kconfig/merge_config.sh -m .config "${SCRIPT_DIR}/qemu/kernel.config"
    make olddefconfig

    log "Building kernel (this takes ~20-30 min on first run)..."
    make -j"$(nproc)" bzImage 2>&1 | tee /tmp/kbuild.log | \
        grep -E "^\s*(CC|LD|AR|error:|warning: )" || \
        { grep "error:" /tmp/kbuild.log | tail -20; exit 1; }

    cp arch/x86/boot/bzImage "${SCRIPT_DIR}/bzImage"
    cd "${SCRIPT_DIR}"
    ok "Kernel built: bzImage"
fi

# ── 5. Busybox (static) ──────────────────────────────────────────────────────
BUSYBOX_DIR="busybox-${BUSYBOX_VER}"
BUSYBOX_TAG="${BUSYBOX_VER//./_}"   # 1.36.1 → 1_36_1
BUSYBOX_REPO="https://github.com/mirror/busybox"

if [[ -d "busybox-install" ]]; then
    ok "Busybox already built, skipping."
else
    if [[ ! -d "${BUSYBOX_DIR}" ]]; then
        log "Cloning busybox ${BUSYBOX_VER} (tag ${BUSYBOX_TAG})..."
        git clone --depth=1 --branch "${BUSYBOX_TAG}" "${BUSYBOX_REPO}" "${BUSYBOX_DIR}"
    fi

    log "Building static busybox..."
    cd "${BUSYBOX_DIR}"
    make defconfig
    sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
    sed -i 's/CONFIG_STATIC=n/CONFIG_STATIC=y/' .config
    echo "CONFIG_STATIC=y" >> .config
    sed -i 's/CONFIG_TC=y/CONFIG_TC=n/' .config
    echo "CONFIG_TC=n" >> .config
    make oldconfig < /dev/null || true
    make -j"$(nproc)"
    make install CONFIG_PREFIX="${SCRIPT_DIR}/busybox-install"
    cd "${SCRIPT_DIR}"
    ok "Busybox installed to busybox-install/"
fi

# ── 6. Dropbear (static SSH server) ──────────────────────────────────────────
# syzkaller connects to VMs via SSH. We bake a static dropbear into the initramfs
# so the VM runs a minimal SSH server without needing a full OS.
DROPBEAR_DIR="dropbear-${DROPBEAR_VER}"
DROPBEAR_TAR="${DROPBEAR_DIR}.tar.bz2"
DROPBEAR_URL="https://matt.ucc.asn.au/dropbear/releases/${DROPBEAR_TAR}"

if [[ -f "dropbear-install/sbin/dropbear" ]]; then
    ok "Dropbear already built, skipping."
else
    if [[ ! -d "${DROPBEAR_DIR}" ]]; then
        log "Downloading dropbear ${DROPBEAR_VER}..."
        wget -c --timeout=30 --tries=2 "${DROPBEAR_URL}"
        tar -xjf "${DROPBEAR_TAR}"
        rm -f "${DROPBEAR_TAR}"
    fi

    log "Building static dropbear (SSH server + dropbearkey)..."
    cd "${DROPBEAR_DIR}"
    ./configure \
        --prefix="${SCRIPT_DIR}/dropbear-install" \
        --disable-syslog \
        --disable-pam \
        --disable-utmp \
        --disable-wtmp \
        --disable-lastlog \
        CFLAGS="-O2 -static" \
        LDFLAGS="-static"

    # Build only the server + key generator (not the client)
    make PROGRAMS="dropbear dropbearkey" -j"$(nproc)"
    mkdir -p "${SCRIPT_DIR}/dropbear-install/sbin"
    cp dropbear "${SCRIPT_DIR}/dropbear-install/sbin/dropbear"
    cp dropbearkey "${SCRIPT_DIR}/dropbear-install/sbin/dropbearkey"
    cd "${SCRIPT_DIR}"
    ok "Dropbear installed to dropbear-install/"
fi

# ── 7. SSH key pair ───────────────────────────────────────────────────────────
# syz-manager uses qemu/id_rsa to SSH into VMs.
# The matching public key is baked into initramfs as authorized_keys.
if [[ -f "qemu/id_rsa" ]]; then
    ok "SSH key pair already exists."
else
    log "Generating SSH key pair for syzkaller ↔ VM access..."
    ssh-keygen -t rsa -b 4096 -f qemu/id_rsa -N "" -C "syz-manager@usb-fuzz"
    ok "SSH keys: qemu/id_rsa (private), qemu/id_rsa.pub (public)"
fi

# ── 8. Initramfs ─────────────────────────────────────────────────────────────
if [[ -f "qemu/initramfs.cpio.gz" ]]; then
    ok "qemu/initramfs.cpio.gz already exists, skipping."
else
    log "Assembling initramfs..."
    rm -rf initramfs
    mkdir -p initramfs/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,tmp,run,lib,lib64,etc,etc/dropbear,root/.ssh}

    # Busybox — all applets as symlinks
    cp busybox-install/bin/busybox initramfs/bin/busybox
    (cd initramfs && bin/busybox --list | while read applet; do
        ln -sf /bin/busybox bin/"${applet}" 2>/dev/null || true
    done)
    ln -sf /bin/busybox initramfs/bin/sh
    ln -sf /bin/busybox initramfs/sbin/ip
    ln -sf /bin/busybox initramfs/sbin/modprobe

    # Dropbear (static, so no shared libraries needed)
    cp dropbear-install/sbin/dropbear    initramfs/sbin/dropbear
    cp dropbear-install/sbin/dropbearkey initramfs/sbin/dropbearkey
    chmod +x initramfs/sbin/dropbear initramfs/sbin/dropbearkey

    # Bake in the SSH public key so syzkaller can authenticate
    cp qemu/id_rsa.pub initramfs/root/.ssh/authorized_keys
    chmod 700 initramfs/root/.ssh
    chmod 600 initramfs/root/.ssh/authorized_keys

    # init script
    cp qemu/init initramfs/init
    chmod +x initramfs/init

    log "Packing initramfs..."
    (cd initramfs && find . | cpio -oH newc 2>/dev/null | gzip -9) > qemu/initramfs.cpio.gz
    ok "qemu/initramfs.cpio.gz: $(du -sh qemu/initramfs.cpio.gz | cut -f1)"
fi

# ── 9. Disk image (required by syzkaller's QEMU VM type) ─────────────────────
# syzkaller validates that the image file exists even when booting from
# kernel + initramfs. We create a minimal ext4 image; QEMU attaches it as
# an unused second drive — the actual rootfs comes from the initramfs.
if [[ -f "qemu/disk.img" ]]; then
    ok "qemu/disk.img already exists, skipping."
else
    log "Creating minimal disk image (128M)..."
    dd if=/dev/zero of=qemu/disk.img bs=1M count=128 status=none
    mkfs.ext4 -q qemu/disk.img
    ok "qemu/disk.img created."
fi

# ── 10. Workdirs ──────────────────────────────────────────────────────────────
for profile in raw-gadget gadget-fw usbfs; do
    mkdir -p "workdir-${profile}"
done
ok "Workdirs created: workdir-raw-gadget/ workdir-gadget-fw/ workdir-usbfs/"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
ok "Setup complete. Next steps:"
echo "  1. Start fuzzing:    bash run-fuzzers.sh [--raw-gadget|--gadget-fw|--usbfs|--all]"
echo "  2. Web UI:           http://127.0.0.1:56741  (raw-gadget profile)"
echo "                       http://127.0.0.1:56742  (gadget-fw profile)"
echo "                       http://127.0.0.1:56743  (usbfs profile)"
echo "  3. Verify QEMU:      qemu-system-x86_64 -kernel bzImage -initrd qemu/initramfs.cpio.gz \\"
echo "                         -nographic -append 'console=ttyS0 quiet' -m 2048M"
echo "  4. Stop:             bash cleanup.sh"
