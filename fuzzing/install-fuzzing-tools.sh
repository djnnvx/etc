#!/bin/env bash

# Adapted from (tested on ubuntu 22.04):
# https://github.com/20urc3/Talks/tree/main/leHack

set -euo pipefail

export LLVM_VERSION=18

install_wsl_cuda() { # not mandatory but could always be useful

    wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.1-1_all.deb
    sudo dpkg -i cuda-keyring_1.1-1_all.deb
    sudo apt-get update
    sudo apt-get -y install cuda-toolkit-12-5
}

install_deps() {  # GCC is required
    echo "[+] installing AFL deps"

    sudo apt-get update
    sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev

    # try to install llvm ${LLVM_VERSION} and install the distro default if that fails
    sudo apt-get install -y lld-${LLVM_VERSION} llvm-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev clang-${LLVM_VERSION} || sudo apt-get install -y lld llvm llvm-dev clang
    sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

    sudo apt-get install -y ninja-build # for QEMU mode
    sudo apt-get install -y cpio libcapstone-dev # for Nyx mode
    sudo apt-get install -y wget curl # for Frida mode
    sudo apt-get install -y python3-pip # for Unicorn mode


    sudo apt-get install -y gcc

    sudo apt-get install -y build-essential make python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools python3-pip \
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev \
        ninja-build pipx binutils-dev cppcheck

    pipx ensurepath

    # pipx install unicorn
    pipx install semgrep
}

install_llvm() { # expects llvm version
    echo "[+] installing LLVM ${LLVM_VERSION}"

    wget -c https://apt.llvm.org/llvm.sh && chmod +x llvm.sh
    sudo ./llvm.sh "${LLVM_VERSION}"

    export LLVM_CONFIG=llvm-config-${LLVM_VERSION}
    echo "Defaults env_keep += \"${LLVM_CONFIG}\"" | sudo EDITOR='tee -a' visudo
}

install_aflpp() {
    echo "[+] installing AFL++"

    git clone https://github.com/AFLplusplus/AFLplusplus aflpp --branch=stable
    cd aflpp ; make && sudo make install ; cd -
}

install_libafl() {
    echo "[+] installing libAFL"

    curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf > install-rust.sh
    chmod +x install-rust.sh

    # pressing enter for default install
    printf "\n\n\n" | ./install-rust.sh

    . "$HOME/.cargo/env"

    cargo install cargo-make
    git clone https://github.com/AFLplusplus/LibAFL libafl --branch=main
    cd libafl ; cargo build --release ; cd ..
}

install_honggfuzz() {
    echo "[+] installing honggfuzz"

    sudo apt-get -y  install binutils-dev libunwind-dev libblocksruntime-dev
    git clone https://github.com/google/honggfuzz

    cd honggfuzz ; make ; cd ..
}

install_clang_static() {
    echo "[+] installing clang-static-analyzer"

    # sudo apt-get install -y clang clang-tools

    git clone https://github.com/llvm/llvm-project.git

    mkdir -p llvm-project/build
    cd llvm-project/build

    cmake -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm
    make && sudo make install

    cd -
}

##
## Main function
##

sudo apt update && sudo apt upgrade -y

install_deps
install_llvm
install_aflpp
install_libafl
install_honggfuzz

# install_wsl_cuda

install_clang_static
