#!/bin/bash
set -e

# Variables (edit if needed)
REPO_URL="https://github.com/proftpd/proftpd.git"
REPO_DIR="proftpd"
CC=${CC:-gcc}
CXX=${CXX:-g++}
CFLAGS=${CFLAGS:-"-O2"}
CXXFLAGS=${CXXFLAGS:-"-O2"}
LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:-"-fsanitize=fuzzer"}
OUT_DIR="fuzz_out"
SEED_CORPUS_URL="https://github.com/dvyukov/go-fuzz-corpus.git"

# Clone the repository
git clone "$REPO_URL"
cd "$REPO_DIR"

# Configure and build
export LDFLAGS="${CFLAGS}"
./configure --enable-ctrls
make -j"$(nproc)"

# Patch src/main.c for fuzzing
sed 's/int main(/int main2(/g' -i src/main.c

# Compile main.c again
NEW_CC_FLAG="$CC $CFLAGS -DHAVE_CONFIG_H -DLINUX  -I. -I./include"
$NEW_CC_FLAG -c src/main.c -o src/main.o
rm src/ftpdctl.o || true

# Create fuzz_lib.a from all object files
find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;

# Build fuzzer (assumes tests/fuzzing/fuzzer.c exists)
mkdir -p "$OUT_DIR"
$NEW_CC_FLAG -c tests/fuzzing/fuzzer.c -o fuzzer.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o -o "$OUT_DIR/fuzzer" \
    src/scoreboard.o \
    lib/prbase.a \
    fuzz_lib.a \
    -Llib \
    -lcrypt -pthread

# Build seed corpus
git clone "$SEED_CORPUS_URL"
zip "$OUT_DIR/fuzzer_seed_corpus.zip" go-fuzz-corpus/json/corpus/*

echo "=== Build complete ==="
echo "To run fuzzing:"
echo "$OUT_DIR/fuzzer -runs=1000000 $OUT_DIR/fuzzer_seed_corpus.zip"
