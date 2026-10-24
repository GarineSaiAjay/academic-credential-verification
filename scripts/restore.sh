#!/usr/bin/env bash
# Restores a backup made by scripts/backup.sh, REPLACING everything in the database.
# Usage: scripts/restore.sh BACKUP_FILE [--yes]
#
#   BACKUP_PASSPHRASE  needed for *.enc backups
#   COMPOSE_FILE       e.g. docker-compose.prod.yml for the production stack
#
# Disaster recovery on a new host: copy .env (with the SAME ENCRYPTION_KEY), run `docker compose up -d postgres`,
# then this script. If the database already holds data, --yes is required (it is dropped and recreated).
# The backend is stopped during the restore and started afterwards; on start it applies any newer migrations,
# checks that every stored key opens under ENCRYPTION_KEY, and refuses to run if one does not.
set -euo pipefail
cd "$(dirname "$0")/.."

FILE=${1:-}; YES=${2:-}
[ -f "$FILE" ] || { echo "usage: $0 BACKUP_FILE [--yes]" >&2; exit 2; }

if [ -f "$FILE.sha256" ]; then
  EXPECT=$(cut -d' ' -f1 "$FILE.sha256")
  ACTUAL=$( { shasum -a 256 "$FILE" 2>/dev/null || sha256sum "$FILE"; } | cut -d' ' -f1)
  [ "$EXPECT" = "$ACTUAL" ] || { echo "the checksum does not match: the backup is damaged or was altered; nothing was changed" >&2; exit 1; }
else
  echo "warning: no $FILE.sha256 next to the backup, so its integrity cannot be checked" >&2
fi

stream() {
  case "$FILE" in
    *.enc)
      [ -n "${BACKUP_PASSPHRASE:-}" ] || { echo "this backup is encrypted: set BACKUP_PASSPHRASE" >&2; return 1; }
      openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_PASSPHRASE < "$FILE" ;;
    *) cat "$FILE" ;;
  esac
}

# Read the whole backup before touching anything: a wrong passphrase or a damaged file must not cost the live data.
stream | docker compose exec -T postgres pg_restore --list >/dev/null 2>&1 \
  || { echo "cannot read the backup (wrong BACKUP_PASSPHRASE, or not a backup from scripts/backup.sh); nothing was changed" >&2; exit 1; }

PSQL="docker compose exec -T postgres psql -U acvs -d postgres -qAt -v ON_ERROR_STOP=1"
EXISTING=$($PSQL -c "SELECT count(*) FROM pg_database WHERE datname = 'acvs'")
USERS=0
if [ "$EXISTING" = 1 ]; then
  USERS=$(docker compose exec -T postgres psql -U acvs -d acvs -qAt -c "SELECT CASE WHEN to_regclass('public.users') IS NULL THEN 0 ELSE (SELECT count(*) FROM users) END" 2>/dev/null || echo 0)
fi
if [ "${USERS:-0}" != 0 ] && [ "$YES" != "--yes" ]; then
  echo "the database already holds data ($USERS users). Restoring replaces ALL of it. Run again with --yes to proceed." >&2
  exit 1
fi

docker compose stop backend >/dev/null 2>&1 || true
$PSQL -c "DROP DATABASE IF EXISTS acvs WITH (FORCE)" >/dev/null
$PSQL -c "CREATE DATABASE acvs OWNER acvs" >/dev/null
stream | docker compose exec -T postgres pg_restore -U acvs -d acvs --no-owner --exit-on-error \
  || { echo "the restore failed part-way; the database is incomplete. Restore again or investigate before starting the backend." >&2; exit 1; }

echo "restored; starting the backend"
docker compose up -d --wait backend >/dev/null 2>&1 || {
  echo "the backend did not become healthy. Its log says why (most often: ENCRYPTION_KEY is not the key the backup was made with):" >&2
  docker compose logs --tail 5 backend >&2
  exit 1
}
CHAIN=$(docker compose exec -T backend curl -fsS http://localhost:8000/api/v1/ledger/verify)
echo "ledger check after restore: $CHAIN"
echo "$CHAIN" | grep -q '"ok":true' || { echo "the restored ledger does not verify" >&2; exit 1; }
echo "restore complete"
