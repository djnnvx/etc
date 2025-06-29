#!/bin/bash


afl-fuzz -i inputs -o output -- ./test @@
