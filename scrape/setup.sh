#!/bin/bash
set -euo pipefail
cd "$(cd "$(dirname "${0}")" && pwd)"

command -v uv >/dev/null || { echo "[!] uv not found: https://docs.astral.sh/uv/" >&2; exit 1; }

uv venv
uv pip install -q curl_cffi

echo "[+] Done. Run: uv run ./scrape.py"
