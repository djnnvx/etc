#!/bin/bash
# backup-crashes.sh — archive unique AFL++ crashes with deduplication.
#
# Intended to run as a cron job or in a background loop:
#   crontab -e
#   */15 * * * *  /path/to/usbip/backup-crashes.sh >> /tmp/crash-backup.log 2>&1
#
# Or in a loop from another terminal:
#   while sleep 900; do bash backup-crashes.sh; done
#
# What it does:
#   1. Scans output/*/crashes/ for crash files newer than .last_backup stamp
#   2. Deduplicates by sha256 (avoids archiving the same crash twice)
#   3. Compresses unique new crashes into backups/crashes_YYYYMMDD_HHMMSS.tar.gz
#   4. Updates .last_backup stamp

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

OUTPUT_DIR="${SCRIPT_DIR}/output"
BACKUP_DIR="${SCRIPT_DIR}/backups"
STAMP_FILE="${SCRIPT_DIR}/.last_backup"
SEEN_HASHES="${SCRIPT_DIR}/.seen_crash_hashes"

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

mkdir -p "${BACKUP_DIR}"
touch "${STAMP_FILE}" "${SEEN_HASHES}"

# ── find new crash files ──────────────────────────────────────────────────────
TMPLIST="$(mktemp)"
trap "rm -f ${TMPLIST}" EXIT

# Collect crash files from all AFL++ fuzzer subdirs
find "${OUTPUT_DIR}" -path "*/crashes/id:*" -newer "${STAMP_FILE}" \
    -not -name "README.txt" \
    2>/dev/null > "${TMPLIST}" || true

TOTAL=$(wc -l < "${TMPLIST}")
if [[ "${TOTAL}" -eq 0 ]]; then
    log "No new crashes since last backup."
    exit 0
fi

log "Found ${TOTAL} new crash file(s) since last backup."

# ── deduplicate by sha256 ─────────────────────────────────────────────────────
TMPSTAGE="$(mktemp -d)"
trap "rm -rf ${TMPSTAGE} ${TMPLIST}" EXIT

NEW=0
while IFS= read -r crash; do
    hash="$(sha256sum "${crash}" | cut -d' ' -f1)"
    if ! grep -qF "${hash}" "${SEEN_HASHES}" 2>/dev/null; then
        cp "${crash}" "${TMPSTAGE}/"
        echo "${hash}" >> "${SEEN_HASHES}"
        NEW=$((NEW + 1))
    fi
done < "${TMPLIST}"

if [[ "${NEW}" -eq 0 ]]; then
    log "All ${TOTAL} new files were duplicates. Nothing to archive."
    touch "${STAMP_FILE}"
    exit 0
fi

# ── create archive ────────────────────────────────────────────────────────────
ARCHIVE="${BACKUP_DIR}/crashes_$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czf "${ARCHIVE}" -C "${TMPSTAGE}" .

SIZE="$(du -sh "${ARCHIVE}" | cut -f1)"
log "Archived ${NEW} unique crash(es) → ${ARCHIVE} (${SIZE})"

# Update stamp AFTER successful archive
touch "${STAMP_FILE}"

# ── prune old backups (keep last 50) ─────────────────────────────────────────
ls -t "${BACKUP_DIR}"/crashes_*.tar.gz 2>/dev/null | tail -n +51 | while read old; do
    rm -f "${old}"
    log "Pruned old backup: $(basename "${old}")"
done

exit 0
