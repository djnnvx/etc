#!/bin/bash

set -euo

sudo apt install libtool

git clone https://gitlab.freedesktop.org/freetype/freetype.git
cd freetype
./autogen.sh # Generates the configure file
./configure CC=afl-clang-fast CXX=afl-clang-fast++ CFLAGS="-O1" CXXFLAGS="-O1"
make

mkdir -p ../targets

cp -r include ../targets/include
cp ./objs/libs/libfreetype.a ../targets/libfreetype.a
