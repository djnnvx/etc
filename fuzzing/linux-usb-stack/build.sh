#!/bin/bash
# build.sh — incremental rebuild for the linux-usb-stack fuzzing environment.
#
# Re-runs after kernel or syzkaller source changes.
# Does NOT re-download sources; run setup.sh for first-time setup.
#
# Usage:
#   bash build.sh              # rebuild kernel + syzkaller + initramfs
#   bash build.sh --kernel     # rebuild kernel only
#   bash build.sh --syzkaller  # rebuild syzkaller only
#   bash build.sh --initramfs  # repack initramfs only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

DO_KERNEL=1
DO_SYZKALLER=1
DO_INITRAMFS=1

if [[ $# -gt 0 ]]; then
    DO_KERNEL=0; DO_SYZKALLER=0; DO_INITRAMFS=0
    for arg in "$@"; do
        [[ "${arg}" == "--kernel"     ]] && DO_KERNEL=1
        [[ "${arg}" == "--syzkaller"  ]] && DO_SYZKALLER=1
        [[ "${arg}" == "--initramfs"  ]] && DO_INITRAMFS=1
    done
fi

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
die()  { echo "[!] $*" >&2; exit 1; }

# ── Go path ──────────────────────────────────────────────────────────────────
for cand in "${SCRIPT_DIR}/go/bin/go" /usr/local/go/bin/go; do
    [[ -x "${cand}" ]] && export PATH="$(dirname "${cand}"):${PATH}" && break
done
export GOPATH="${SCRIPT_DIR}/gopath"

# ── kernel ───────────────────────────────────────────────────────────────────
if [[ "${DO_KERNEL}" -eq 1 ]]; then
    [[ -d "linux" ]] || die "linux/ not found. Run setup.sh first."
    log "Rebuilding kernel..."
    cd linux
    make -j"$(nproc)" bzImage 2>&1 | tee /tmp/kbuild.log | \
        grep -E "^\s*(CC|LD|AR|error:|warning: )" || \
        { grep "error:" /tmp/kbuild.log | tail -20; exit 1; }
    cp arch/x86/boot/bzImage "${SCRIPT_DIR}/bzImage"
    cd "${SCRIPT_DIR}"
    ok "Kernel rebuilt: bzImage"
fi

# ── syzkaller ─────────────────────────────────────────────────────────────────
if [[ "${DO_SYZKALLER}" -eq 1 ]]; then
    [[ -d "syzkaller" ]] || die "syzkaller/ not found. Run setup.sh first."
    log "Rebuilding syzkaller..."
    cd syzkaller
    make all -j"$(nproc)" 2>&1 | tail -5
    cd "${SCRIPT_DIR}"
    ok "syzkaller rebuilt."
fi

# ── initramfs ─────────────────────────────────────────────────────────────────
if [[ "${DO_INITRAMFS}" -eq 1 ]]; then
    [[ -d "busybox-install" ]]            || die "busybox-install/ not found. Run setup.sh first."
    [[ -f "dropbear-install/sbin/dropbear" ]] || die "dropbear not found. Run setup.sh first."
    [[ -f "qemu/id_rsa.pub" ]]            || die "qemu/id_rsa.pub not found. Run setup.sh first."

    log "Repacking initramfs..."
    rm -rf initramfs
    mkdir -p initramfs/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,tmp,run,lib,lib64,etc,etc/dropbear,root/.ssh}

    cp busybox-install/bin/busybox initramfs/bin/busybox
    (cd initramfs && bin/busybox --list | while read applet; do
        ln -sf /bin/busybox bin/"${applet}" 2>/dev/null || true
    done)
    ln -sf /bin/busybox initramfs/bin/sh
    ln -sf /bin/busybox initramfs/sbin/ip
    ln -sf /bin/busybox initramfs/sbin/modprobe

    cp dropbear-install/sbin/dropbear    initramfs/sbin/dropbear
    cp dropbear-install/sbin/dropbearkey initramfs/sbin/dropbearkey
    chmod +x initramfs/sbin/dropbear initramfs/sbin/dropbearkey

    cp qemu/id_rsa.pub initramfs/root/.ssh/authorized_keys
    chmod 700 initramfs/root/.ssh
    chmod 600 initramfs/root/.ssh/authorized_keys

    cp qemu/init initramfs/init
    chmod +x initramfs/init

    (cd initramfs && find . | cpio -oH newc 2>/dev/null | gzip -9) > qemu/initramfs.cpio.gz
    ok "initramfs repacked: $(du -sh qemu/initramfs.cpio.gz | cut -f1)"
fi
