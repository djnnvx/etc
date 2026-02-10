#!/bin/env bash

set -euo pipefail

export LLVM_VERSION=18

install_llvm() {
    echo "[+] installing LLVM ${LLVM_VERSION}"

    # Download the official script
    wget -c https://apt.llvm.org/llvm.sh && chmod +x llvm.sh

    # Detect codename; if it's unknown or "questing", fallback to "noble"
    CODENAME=$(lsb_release -s -c)
    if [[ "$CODENAME" == "questing" || "$CODENAME" == "oracular" || "$CODENAME" == "plucky" ]]; then
        echo "[!] Non-LTS or unknown distro detected ($CODENAME). Using 'noble' repositories for LLVM."
        # We manually run the addition to avoid the script's auto-detection failure
        sudo apt-get install -y software-properties-common
        wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/noble/ llvm-toolchain-noble-${LLVM_VERSION} main" | sudo tee /etc/apt/sources.list.d/llvm.list
        sudo apt-get update
        sudo apt-get install -y clang-${LLVM_VERSION} lldb-${LLVM_VERSION} lld-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev
    else
        sudo ./llvm.sh "${LLVM_VERSION}"
    fi

    export LLVM_CONFIG=llvm-config-${LLVM_VERSION}
    echo "Defaults env_keep += \"LLVM_CONFIG\"" | sudo tee /etc/sudoers.d/llvm_env
}

install_deps() {
    echo "[+] installing AFL deps"
    sudo apt-get update

    # Install core build tools first
    sudo apt-get install -y build-essential python3-dev automake cmake git flex bison \
        libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev \
        ninja-build cpio libcapstone-dev wget curl python3-pip pipx binutils-dev \
        cppcheck libunwind-dev libblocksruntime-dev

    # Get GCC version for plugin-dev headers
    GCC_VER=$(gcc --version | head -n1 | cut -d' ' -f3 | cut -d'.' -f1)
    sudo apt-get install -y "gcc-${GCC_VER}-plugin-dev" "libstdc++-${GCC_VER}-dev"

    pipx ensurepath
}

install_aflpp() {
    echo "[+] installing AFL++"
    if [ ! -d "aflpp" ]; then
        git clone https://github.com/AFLplusplus/AFLplusplus aflpp --branch=stable
    fi
    cd aflpp
    # Ensure LLVM_CONFIG is picked up
    export LLVM_CONFIG=llvm-config-${LLVM_VERSION}
    make clean
    make && sudo make install
    cd -
}

install_libafl() {
    echo "[+] installing libAFL"
    if ! command -v rustc &> /dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    cargo install cargo-make || true
    if [ ! -d "libafl" ]; then
        git clone https://github.com/AFLplusplus/LibAFL libafl --branch=main
    fi
    cd libafl && cargo build --release && cd ..
}

install_honggfuzz() {
    echo "[+] installing honggfuzz"
    if [ ! -d "honggfuzz" ]; then
        git clone https://github.com/google/honggfuzz
    fi
    cd honggfuzz && make && sudo make install && cd ..
}

sudo apt update && sudo apt upgrade -y
install_deps
install_llvm
install_aflpp
install_libafl
install_honggfuzz

echo "[*] Installation complete. Please restart your terminal or run 'source ~/.bashrc'"
