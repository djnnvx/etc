#!/bin/bash

afl-clang-fast test-harness.c -I../targets/include -L../targets/ -lfreetype -o test
