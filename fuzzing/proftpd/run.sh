#!/bin/bash
set -e

REPO_URL="https://github.com/proftpd/proftpd.git"
REPO_DIR="proftpd"
REPO_VERSION="1.3.9"

OUT_DIR="fuzz_out"
SEED_CORPUS_URL="https://github.com/dvyukov/go-fuzz-corpus.git"
FUZZ_TARGET="json_fuzzer"

CC=${CC:-clang}
CXX=${CXX:-clang++}
CFLAGS=${CFLAGS:-"-O2 -fsanitize=fuzzer,address -fPIC"}
CXXFLAGS=${CXXFLAGS:-"-O2 -fsanitize=fuzzer,address -fPIC"}

echo "Cloning ProFTPD repository..."
if [ ! -d "$REPO_DIR" ]; then
    git clone "$REPO_URL" --branch "$REPO_VERSION"
fi
cd "$REPO_DIR"

echo "Configuring and building ProFTPD..."
make clean
./configure --enable-ctrls --enable-devel=stacktrace
make -j"$(nproc)"

echo "Building the fuzzer executable..."
mkdir -p "$OUT_DIR"
$CC $CFLAGS -c tests/fuzzing/json_fuzzer.c -o "$OUT_DIR/$FUZZ_TARGET.o" -I. -I./include -DHAVE_CONFIG_H -DLINUX

CORE_OBJS=$(find src/ -name "*.o" ! -name "main.o" ! -name "ftpdctl.o" | tr '\n' ' ')
MODULES_OBJS=$(find modules/ -name "*.o" | tr '\n' ' ')

# Link the fuzzer with all relevant object files and libraries
# FIXME(djnn): this is currently broken x.x
$CXX $CXXFLAGS "$OUT_DIR/$FUZZ_TARGET.o" \
    $CORE_OBJS \
    $MODULES_OBJS \
    lib/prbase.a \
    -o "$OUT_DIR/$FUZZ_TARGET" -Llib -lcrypt -pthread

echo "Building seed corpus..."
cd ..
if [ ! -d "go-fuzz-corpus" ]; then
    git clone "$SEED_CORPUS_URL"
fi
zip -r "$REPO_DIR/$OUT_DIR/${FUZZ_TARGET}_seed_corpus.zip" go-fuzz-corpus/json/corpus/

echo "Build complete."
echo "To run the fuzzer:"
echo "./$REPO_DIR/$OUT_DIR/$FUZZ_TARGET $OUT_DIR/${FUZZ_TARGET}_seed_corpus.zip"
echo
