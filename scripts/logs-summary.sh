#!/bin/bash

# --- Nginx Log Summary Script ---
#
# This script scans all Nginx logs (compressed and uncompressed)
# in /var/log/nginx and prints the top N most common
# visited links, client IPs, user agents, and errors.
#
# --- USAGE ---
#
# Run with sudo and an optional number:
#   sudo ./log-summary.sh [NUMBER]
#
#   [NUMBER]: The number of top results to show (e.g., 10, 50, 100).
#             Defaults to 50 if not provided.
#
# Get help:
#   ./log-summary.sh -h
#
# ---

# --- Argument Parsing ---

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    head -n 20 "$0"
    exit 0
fi

DEFAULT_LIMIT=50
LIMIT="${1:-$DEFAULT_LIMIT}" # Use $1 if provided, else use the default

if ! [[ "$LIMIT" =~ ^[0-9]+$ ]]; then
    echo "Error: Argument must be a positive number." >&2
    echo "Usage: sudo $0 [NUMBER]" >&2
    echo "   or: $0 -h" >&2
    exit 1
fi

set -e

# --- Script Body ---

echo "Navigating to /var/log/nginx..."
cd /var/log/nginx

print_header() {
    echo ""
    echo "============================================="
    echo " $1"
    echo "============================================="
    echo ""
}

echo "Showing Top $LIMIT results for all categories..."

# --- Access Log Analysis ---

print_header "Top $LIMIT Most Visited Links"
(cat access.log access.log.1 2>/dev/null ; zcat access.log.*.gz 2>/dev/null) | \
    awk -F'"' '{ print $2 }' | awk '{ print $2 }' | \
    sort | uniq -c | sort -nr | head -n "$LIMIT"

print_header "Top $LIMIT Client IPs"
(cat access.log access.log.1 2>/dev/null ; zcat access.log.*.gz 2>/dev/null) | \
    awk -F'"' 'NF > 0 { print $(NF-1) }' | awk -F, '{ print $1 }' | tr -d ' ' | \
    sort | uniq -c | sort -nr | head -n "$LIMIT"

print_header "Top $LIMIT User Agents"
(cat access.log access.log.1 2>/dev/null ; zcat access.log.*.gz 2>/dev/null) | \
    awk -F'"' 'NF > 3 { print $(NF-3) }' | \
    sort | uniq -c | sort -nr | head -n "$LIMIT"


# --- Error Log Analysis ---

print_header "Top $LIMIT Nginx Errors"
# This command strips the timestamp and any client/request info
# to group similar errors together.
(cat error.log error.log.1 2>/dev/null ; zcat error.log.*.gz 2>/dev/null) | \
    awk -F'] ' '{print $2}' | awk -F',' '{print $1}' | \
    sort | uniq -c | sort -nr | head -n "$LIMIT"

echo ""
echo "Done."
