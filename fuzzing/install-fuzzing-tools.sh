#!/bin/env bash

set -euo pipefail

export LLVM_VERSION=18
export LLVM_CONFIG=llvm-config-18

export CARGO_HOME="$HOME/.cargo"
export RUSTUP="$CARGO_HOME/bin/rustup"
export CARGO="$CARGO_HOME/bin/cargo"
export RUSTC="$CARGO_HOME/bin/rustc"

# Remove previously failed repository attempts if any
sudo rm -f /etc/apt/sources.list.d/archive_uri-http_apt_llvm_org_questing_-questing.list
sudo rm -f /etc/apt/sources.list.d/llvm.list

install_deps() {
    echo "[+] Installing system dependencies"
    sudo apt-get update
    sudo apt-get install -y build-essential python3-dev automake cmake git flex bison \
        libglib2.0-dev libpixman-1-dev python3-setuptools libgtk-3-dev \
        ninja-build cpio libcapstone-dev wget curl python3-pip pipx binutils-dev \
        cppcheck libunwind-dev libblocksruntime-dev gpg software-properties-common

    # Get GCC version for plugin headers
    GCC_VER=$(gcc --version | head -n1 | cut -d' ' -f3 | cut -d'.' -f1)
    sudo apt-get install -y "gcc-${GCC_VER}-plugin-dev" "libstdc++-${GCC_VER}-dev"
}

install_rust() {
    echo "[+] Installing/Updating Rust"

    if [ ! -f "$RUSTUP" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    fi

    # Explicitly update to latest stable (1.89+)
    "$RUSTUP" update stable
    "$RUSTUP" default stable

    echo "[*] Verified Rust version: $("$RUSTC" --version)"
}

install_llvm() {
    echo "[+] Installing LLVM ${LLVM_VERSION}"

    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo gpg --dearmor --yes -o /usr/share/keyrings/llvm-archive-keyring.gpg

    # Using 'noble' because Ubuntu 25 (plucky/oracular) isn't on the LLVM repo servers yet
    echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/noble/ llvm-toolchain-noble-${LLVM_VERSION} main" | sudo tee /etc/apt/sources.list.d/llvm.list

    sudo apt-get update
    sudo apt-get install -y clang-${LLVM_VERSION} lldb-${LLVM_VERSION} lld-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev

    # Ensure LLVM_CONFIG is kept for sudo make install steps
    echo "Defaults env_keep += \"LLVM_CONFIG\"" | sudo tee /etc/sudoers.d/llvm_env
}

install_libafl() {
    echo "[+] Installing LibAFL"

    "$CARGO" install cargo-make || true

    if [ ! -d "libafl" ]; then
        git clone https://github.com/AFLplusplus/LibAFL libafl --branch=main
    fi

    cd libafl
    # Explicitly use the new cargo binary
    "$CARGO" build --release
    cd ..
}

install_aflpp() {
    echo "[+] Installing AFL++"
    [ -d "aflpp" ] || git clone https://github.com/AFLplusplus/AFLplusplus aflpp --branch=stable
    cd aflpp
    make clean
    # Pass LLVM_CONFIG directly to make
    LLVM_CONFIG=llvm-config-${LLVM_VERSION} make
    sudo make install
    cd -
}

install_honggfuzz() {
    echo "[+] Installing honggfuzz"
    [ -d "honggfuzz" ] || git clone https://github.com/google/honggfuzz
    cd honggfuzz
    make
    sudo make install
    cd ..
}

# --- MAIN ---
install_deps
install_rust
install_llvm
install_libafl
install_aflpp
install_honggfuzz
