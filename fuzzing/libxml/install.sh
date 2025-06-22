#!/bin/bash

export LIBXML_VERSION=2.13

set -euo pipefail

git clone https://gitlab.gnome.org/GNOME/libxml2.git && cd libxml2 && git switch ${LIBXML_VERSION}

./autogen.sh

./configure --enable-shared=no

export AFL_USE_UBSAN=1
export AFL_USE_ASAN=1

make CC=afl-clang-fast CXX=afl-clang-fast++ LD=afl-clang-fast

mkdir fuzzing
cp xmllint fuzzing/xmllint_cov

mkdir -p fuzzing/in
cp test/*.xml fuzzing/in/

# sudo afl-system-config
