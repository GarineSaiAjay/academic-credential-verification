#!/usr/bin/env bash
# Takes a consistent backup of the whole database (credentials, approvals, ledger, users, audit log, keys).
# Usage: scripts/backup.sh                       (run from anywhere; uses the compose stack of this checkout)
#
#   BACKUP_DIR         where backups go                                  (default: ./backups, mode 700)
#   BACKUP_PASSPHRASE  encrypt the backup with this passphrase (AES-256, PBKDF2) - strongly recommended, because
#                      the dump holds password hashes and sealed TOTP secrets and signing keys   (default: none)
#   KEEP               keep only the newest N backups in BACKUP_DIR      (default: keep all)
#   COMPOSE_FILE       e.g. docker-compose.prod.yml for the production stack
#
# The backup does NOT contain ENCRYPTION_KEY. Without that key (or a `key-backup`, see the README) the signing
# keys inside the backup cannot be opened. Keep it somewhere else.
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=${BACKUP_DIR:-backups}
umask 077
mkdir -p "$DIR"; chmod 700 "$DIR"
NAME=acvs-$(date -u +%Y%m%dT%H%M%SZ).dump
OUT=$DIR/$NAME

dump() { docker compose exec -T postgres pg_dump -U acvs -Fc --no-owner acvs; }
if [ -n "${BACKUP_PASSPHRASE:-}" ]; then
  [ ${#BACKUP_PASSPHRASE} -ge 12 ] || { echo "BACKUP_PASSPHRASE must be at least 12 characters" >&2; exit 1; }
  OUT=$OUT.enc
  dump | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_PASSPHRASE > "$OUT" || { rm -f "$OUT"; echo "pg_dump failed" >&2; exit 1; }
else
  echo "warning: BACKUP_PASSPHRASE is not set, so this backup is not encrypted" >&2
  dump > "$OUT" || { rm -f "$OUT"; echo "pg_dump failed" >&2; exit 1; }
fi

# A backup you have not read back is a hope, not a backup: make sure it is a complete, readable archive.
if [ -n "${BACKUP_PASSPHRASE:-}" ]; then
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_PASSPHRASE < "$OUT"
else
  cat "$OUT"
fi | docker compose exec -T postgres pg_restore --list > "$OUT.list" || { rm -f "$OUT" "$OUT.list"; echo "the backup could not be read back" >&2; exit 1; }
TABLES=$(grep -c ' TABLE DATA ' "$OUT.list" || true)
rm -f "$OUT.list"
[ "$TABLES" -ge 10 ] || { rm -f "$OUT"; echo "the backup holds only $TABLES tables; refusing to keep it" >&2; exit 1; }

( cd "$DIR" && { shasum -a 256 "$(basename "$OUT")" 2>/dev/null || sha256sum "$(basename "$OUT")"; } > "$(basename "$OUT").sha256" )

if [ -n "${KEEP:-}" ]; then
  # shellcheck disable=SC2012
  ls -1t "$DIR"/acvs-*.dump* 2>/dev/null | grep -v '\.sha256$' | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old" "$old.sha256"
  done
fi
echo "$OUT ($(wc -c < "$OUT" | tr -d ' ') bytes, $TABLES tables with data)"
