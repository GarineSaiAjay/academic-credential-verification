#!/usr/bin/env bash
# Proves that a backup can be restored after losing the whole database, and that migrations can be rolled back.
# Usage: scripts/backup-test.sh
#
# Runs a throwaway copy of the development stack ("acvsbak"). It publishes the same ports as the main dev
# stack, so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

export COMPOSE_PROJECT_NAME=acvsbak
T=$(mktemp -d)
export BACKUP_DIR=$T/backups
trap 'docker compose down -v >/dev/null 2>&1; rm -rf "$T"' EXIT

PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2)
export SEED_DEMO_PASSWORD=$PASS
BASE=http://localhost:3000/api/v1
BODY_C='{"student_id":"STU-1","student_name":"Ada Lovelace","program":"BSc Computer Science","graduation_date":"2025-05-15"}'
fails=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
call() {
  local args=(-s -o "$T/body" -w '%{http_code}' -X "$1" "$BASE$2" -H 'Content-Type: application/json')
  [ -n "${3:-}" ] && args+=(-H "Authorization: Bearer $3")
  [ "$1" = POST ] && args+=(-H "X-Nonce: $(python3 -c 'import uuid; print(uuid.uuid4())')" -H "X-Timestamp: $(date +%s)")
  [ -n "${4:-}" ] && args+=(-d "$4")
  : > "$T/body"; CODE=$(curl "${args[@]}"); BODY=$(cat "$T/body")
}
login() { call POST /auth/login "" "{\"email\":\"$1@university.edu\",\"password\":\"$PASS\"}"; echo "$BODY" | j "d['token']"; }
DBX() { docker compose exec -T postgres psql -U acvs -d acvs -qAt -c "$1" 2>&1; }
verdict() { call GET "/verify/$1"; echo "$BODY" | j "d['verdict']"; }
issue() {
  call POST /credentials "$FAC" "$BODY_C"; local id; id=$(echo "$BODY" | j "d['id']")
  for t in "$EXC" "$REG" "$ADM"; do call POST /credentials/$id/approve "$t"; done; echo "$id"
}
schema() { docker compose exec -T postgres pg_dump -U acvs --schema-only --no-owner acvs | grep -v '^--' | grep -v '^$' | grep -Ev '^.(un)?restrict '; }

echo "== a stack with real history"
docker compose up -d --build --wait >/dev/null 2>&1 || { echo "FAIL: stack did not start"; exit 1; }
FAC=$(login faculty); EXC=$(login examcell); REG=$(login registrar); ADM=$(login admin)
C1=$(issue); C2=$(issue)
call POST /ledger/seal "$ADM"; expect "a block is sealed" "$CODE" 200
call POST /credentials/$C2/revoke "$ADM" '{"reason":"issued in error"}'; expect "one credential is revoked" "$CODE" 200
call POST /auth/totp/setup "$FAC" "{\"password\":\"$PASS\"}"; TSEC=$(echo "$BODY" | j "d['secret']")
call POST /auth/totp/enable "$FAC" "{\"code\":\"$(python3 scripts/totp.py "$TSEC")\"}"; expect "a user turns on two-factor sign-in" "$CODE" 200
AUDIT_BEFORE=$(DBX "SELECT count(*) FROM audit_logs")

echo "== backing up"
export BACKUP_PASSPHRASE="backup-test-passphrase"
OUT=$(scripts/backup.sh 2>&1); echo "$OUT" | tail -1 | grep -q 'acvs-.*\.dump\.enc' && ok "a backup is written" || bad "backup: $OUT"
B=$(ls "$BACKUP_DIR"/acvs-*.dump.enc | head -1)
[ -f "$B.sha256" ] && ok "with a checksum file" || bad "no checksum"
expect "readable only by its owner" "$(stat -c %a "$B" 2>/dev/null || stat -f %Lp "$B")" 600
expect "the directory too" "$(stat -c %a "$BACKUP_DIR" 2>/dev/null || stat -f %Lp "$BACKUP_DIR")" 700
head -c 8 "$B" | grep -q 'Salted__' && ! grep -qa 'Ada Lovelace' "$B" && ok "it is encrypted (no readable data in it)" || bad "backup is not encrypted"
unset BACKUP_PASSPHRASE; OUT=$(scripts/backup.sh 2>&1); echo "$OUT" | grep -q 'not encrypted' && ok "without a passphrase it warns that it is plain" || bad "no warning"
OUT=$(BACKUP_PASSPHRASE=short scripts/backup.sh 2>&1); echo "$OUT" | grep -q 'at least 12' && ok "a short passphrase is refused" || bad "short passphrase accepted"
export BACKUP_PASSPHRASE="backup-test-passphrase"

echo "== changes made after the backup are not in it"
C3=$(issue); expect "a third credential is issued after the backup" "$(verdict "$C3")" VALID

echo "== refusing to restore badly"
OUT=$(scripts/restore.sh "$B" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q -- '--yes' && ok "restoring over live data needs --yes" || bad "restore over data without --yes: $OUT"
expect "and nothing changed" "$(verdict "$C3")" VALID
cp "$B" "$T/damaged.dump.enc"; cp "$B.sha256" "$T/damaged.dump.enc.sha256"; printf 'x' >> "$T/damaged.dump.enc"
OUT=$(scripts/restore.sh "$T/damaged.dump.enc" --yes 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q 'checksum' && ok "a damaged backup is refused by its checksum" || bad "damaged backup: $OUT"
OUT=$(BACKUP_PASSPHRASE=the-wrong-passphrase scripts/restore.sh "$B" --yes 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q 'cannot read the backup' && ok "a wrong passphrase is refused" || bad "wrong passphrase: $OUT"
OUT=$(env -u BACKUP_PASSPHRASE scripts/restore.sh "$B" --yes 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q 'BACKUP_PASSPHRASE' && ok "a missing passphrase is refused" || bad "missing passphrase: $OUT"
expect "after all that, the live data is untouched" "$(verdict "$C3")" VALID

echo "== disaster: the database volume is gone"
docker compose down -v >/dev/null 2>&1
docker compose up -d --wait postgres >/dev/null 2>&1
expect "the new database is empty" "$(DBX "SELECT count(*) FROM pg_tables WHERE schemaname='public'")" 0
OUT=$(scripts/restore.sh "$B" 2>&1); echo "$OUT" | tail -1 | grep -q 'restore complete' && ok "restore onto the empty database works without --yes" || bad "restore: $OUT"
echo "$OUT" | grep -q '"ok":true' && ok "and the restored ledger verifies" || bad "ledger after restore: $OUT"
docker compose up -d --wait >/dev/null 2>&1 || bad "the rest of the stack did not start"

echo "== what came back"
expect "an issued credential still verifies" "$(verdict "$C1")" VALID
expect "the revoked one is still revoked" "$(verdict "$C2")" REVOKED
call GET "/verify/$C3"; expect "the credential issued after the backup is gone, as it should be" "$CODE" 404
expect "the audit log is as it was at the backup" "$(DBX "SELECT count(*) FROM audit_logs")" "$((AUDIT_BEFORE + 0))"
FAC=$(login faculty 2>/dev/null) ; call POST /auth/login "" "{\"email\":\"faculty@university.edu\",\"password\":\"$PASS\"}"
MT=$(echo "$BODY" | j "d.get('mfa_token','')"); [ -n "$MT" ] && ok "a user with two-factor still has to give a code" || bad "two-factor lost: $BODY"
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$(python3 scripts/totp.py "$TSEC" 1)\"}"; expect "and their authenticator still works" "$CODE" 200
FAC=$(echo "$BODY" | j "d['token']"); EXC=$(login examcell); REG=$(login registrar); ADM=$(login admin)
C4=$(issue); expect "new credentials can be issued (the signing keys came back and open)" "$(verdict "$C4")" VALID
call POST /ledger/seal "$ADM"; expect "the ledger keeps growing" "$CODE" 200
expect "and the chain still verifies" "$(curl -s $BASE/ledger/verify | j "d['ok']")" True

echo "== keeping only the newest backups"
for i in 1 2 3; do scripts/backup.sh >/dev/null 2>&1; sleep 1; done
KEEP=2 scripts/backup.sh >/dev/null 2>&1
expect "KEEP=2 leaves two backups" "$(ls "$BACKUP_DIR"/acvs-*.dump* | grep -vc '\.sha256$')" 2
expect "and their checksums" "$(ls "$BACKUP_DIR"/*.sha256 | wc -l | tr -d ' ')" 2

echo "== rolling the schema back"
LATEST=$(DBX "SELECT max(version) FROM _sqlx_migrations")
expect "all nine migrations are applied" "$LATEST" 9
SCHEMA_FULL=$(schema)
OUT=$(scripts/migrate-down.sh 6 2>&1); [ $? -ne 0 ] && ok "rolling back needs --yes" || bad "no --yes needed: $OUT"
OUT=$(SKIP_BACKUP=1 scripts/migrate-down.sh 0 --yes 2>&1); [ $? -ne 0 ] && ok "0001 cannot be undone" || bad "target 0 accepted"
N_BEFORE=$(ls "$BACKUP_DIR"/acvs-*.dump* | grep -vc '\.sha256$')
OUT=$(scripts/migrate-down.sh 6 --yes 2>&1); echo "$OUT" | grep -q 'undid migration(s): 9 8 7' && ok "migrations 9, 8 and 7 are undone" || bad "migrate-down: $OUT"
expect "it took a backup first" "$(ls "$BACKUP_DIR"/acvs-*.dump* | grep -vc '\.sha256$')" "$((N_BEFORE + 1))"
expect "the schema is at version 6" "$(DBX "SELECT max(version) FROM _sqlx_migrations")" 6
expect "the two-factor tables are gone" "$(DBX "SELECT count(*) FROM pg_tables WHERE tablename IN ('user_totp','totp_recovery','password_resets')")" 0
expect "the sessions columns are gone" "$(DBX "SELECT count(*) FROM information_schema.columns WHERE table_name='sessions' AND column_name IN ('ip','user_agent','mfa_pending')")" 0
expect "data from earlier migrations is intact" "$(DBX "SELECT count(*) FROM credentials")" 3
[ "$(docker compose ps --status running --services | grep -c backend)" = 0 ] && ok "the backend was stopped" || bad "backend still running"
SKIP_BACKUP=1 scripts/migrate-down.sh 1 --yes >/dev/null 2>&1; expect "every migration after the first can be undone" "$(DBX "SELECT max(version) FROM _sqlx_migrations")" 1
expect "what remains is the first schema" "$(DBX "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('block_timestamps','credential_events','user_keys','rate_limits')")" 0
docker compose up -d --wait backend >/dev/null 2>&1 && ok "the current backend applies the migrations again on start" || bad "backend did not start after roll-forward"
expect "back at version 9" "$(DBX "SELECT max(version) FROM _sqlx_migrations")" 9
[ "$(schema)" = "$SCHEMA_FULL" ] && ok "and the schema is identical to before the round trip" || { bad "schema differs after the round trip"; diff <(echo "$SCHEMA_FULL") <(schema) | head; }

echo
[ $fails -eq 0 ] && echo "ALL BACKUP CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
