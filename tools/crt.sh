#!/usr/bin/env bash

# little wrapper to query crt.sh service and retrieve a list of domain names
# usage:
# crt.sh djnn.sh

set -euo pipefail


check_installed () {
    # check if dependency is installed
    which "${1}" >/dev/null || { echo "[!] error: please install ${1}." && exit 1 ; }
}


check_installed jq curl sed sort uniq

[ "${#}" -eq 0 ] && { echo "[!] one argument is required" && head -n 5 ${0} && exit 1 ; }

search="$(curl -s "https://crt.sh?q=${1}&output=json")"

echo "${search}" | jq ".[].common_name,.[].name_value" | \
    cut -d'"' -f2 | sed 's/\\n/\n/g' | sed 's/\*.//g' | \
    sed -r 's/([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})//g' | \
    sort | uniq
