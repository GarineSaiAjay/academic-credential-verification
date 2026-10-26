#!/usr/bin/env bash
# Rolls the database schema back to an earlier migration, for a release that has to be withdrawn.
# Usage: scripts/migrate-down.sh TARGET_VERSION --yes     (e.g. 6 keeps migrations 0001-0006 and undoes 0007, 0008)
#
# Each migration has a matching script in backend/migrations-down/ that says what data it loses. Rolling back
# DELETES that data, so a backup is taken first (BACKUP_PASSPHRASE applies; set SKIP_BACKUP=1 to skip it).
# The backend is stopped. Deploy the older release before starting it again, or it will apply the
# migrations again. 0001 cannot be undone (that would be everything): restore a backup instead.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=${1:-}; YES=${2:-}
[[ "$TARGET" =~ ^[0-9]+$ ]] && [ "$TARGET" -ge 1 ] || { echo "usage: $0 TARGET_VERSION(>=1) --yes" >&2; exit 2; }
[ "$YES" = "--yes" ] || { echo "this deletes data; add --yes" >&2; exit 2; }

PSQL="docker compose exec -T postgres psql -U acvs -d acvs -qAt -v ON_ERROR_STOP=1"
APPLIED=$($PSQL -c "SELECT version FROM _sqlx_migrations ORDER BY version DESC")
SQL="BEGIN;"$'\n'
STEPS=""
for v in $APPLIED; do
  [ "$v" -gt "$TARGET" ] || continue
  f=$(ls backend/migrations-down/"$(printf %04d "$v")"_*.sql 2>/dev/null | head -1 || true)
  [ -n "$f" ] || { echo "there is no down script for migration $v; nothing was changed" >&2; exit 1; }
  SQL+="$(cat "$f")"$'\n'"DELETE FROM _sqlx_migrations WHERE version = $v;"$'\n'
  STEPS+=" $v"
done
[ -n "$STEPS" ] || { echo "the database is already at or below version $TARGET"; exit 0; }
SQL+="COMMIT;"

docker compose stop backend >/dev/null 2>&1 || true
if [ -z "${SKIP_BACKUP:-}" ]; then
  echo "backup first:"; scripts/backup.sh
fi
echo "$SQL" | docker compose exec -T postgres psql -U acvs -d acvs -q -v ON_ERROR_STOP=1 >/dev/null
echo "undid migration(s):$STEPS. The schema is now at version $TARGET. The backend is stopped; start the matching older release."
