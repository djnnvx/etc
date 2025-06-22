#!/bin/bash


set -euo pipefail

rm -rf inputs && mkdir inputs

cd inputs
for i in $(seq 1 500); do cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 10 > "${i}.txt"; done
cd -
