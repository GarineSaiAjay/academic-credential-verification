#!/usr/bin/env bash
# Proves that a lost ENCRYPTION_KEY is recoverable from a key backup.
# Usage: scripts/recovery-test.sh
#
# Runs a throwaway compose project ("acvsrec") with its own volumes, so real data is never touched. It
# publishes the same Postgres port as the main stack, so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

dc() { docker compose -p acvsrec "$@"; }
T=$(mktemp -d)
trap 'dc down -v >/dev/null 2>&1; rm -rf "$T"' EXIT

export SEED_DEMO_PASSWORD= BOOTSTRAP_ADMIN_EMAIL=admin@recovery.test BOOTSTRAP_ADMIN_PASSWORD=admin-recovery-pass
export KEY_BACKUP_PASSPHRASE="recovery-test-passphrase"
K1=$(openssl rand -hex 32); K2=$(openssl rand -hex 32)
UPASS="recovery-user-pass1"
fails=0

ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
# api METHOD PATH [TOKEN] [BODY] -> sets CODE and BODY (calls the API from inside the backend container)
api() {
  local out args=(-s -w '\n%{http_code}' -X "$1" "http://localhost:8000/api/v1$2" -H 'Content-Type: application/json')
  [ -n "${3:-}" ] && args+=(-H "Authorization: Bearer $3")
  [ "$1" = POST ] && args+=(-H "X-Nonce: $(python3 -c 'import uuid; print(uuid.uuid4())')" -H "X-Timestamp: $(date +%s)")
  [ -n "${4:-}" ] && args+=(-d "$4")
  out=$(dc exec -T backend curl "${args[@]}"); CODE=${out##*$'\n'}; BODY=${out%$'\n'*}
}
login() { api POST /auth/login "" "{\"email\":\"$1\",\"password\":\"$2\"}"; echo "$BODY" | j "d['token']"; }
issue() { # prints the id of a credential taken through all four stages
  api POST /credentials "$FT" '{"student_id":"S-1","student_name":"Ada Lovelace","program":"BSc","graduation_date":"2025-05-15"}'
  local id; id=$(echo "$BODY" | j "d['id']")
  for t in "$ET" "$RT" "$AT"; do api POST "/credentials/$id/approve" "$t"; done
  echo "$id"
}
verdict() { api GET "/verify/$1"; echo "$BODY" | j "d['verdict']"; }
active_keys() { api GET /keys "$AT"; echo "$BODY" | j "sorted(k['role']+':'+k['public_key'] for k in d['keys'] if k['status']=='active')"; }
wait_exited() { for _ in $(seq 1 30); do [ "$(dc ps -a backend --format '{{.State}}')" = exited ] && return 0; sleep 1; done; return 1; }
restore() { dc run --rm -T -e KEY_BACKUP_PASSPHRASE backend ./server key-restore "$@" 2>&1; }

echo "== set up: sign credentials under the original ENCRYPTION_KEY"
export ENCRYPTION_KEY=$K1
dc up -d --build --wait postgres backend >/dev/null 2>&1 || { echo "FAIL: stack did not start"; exit 1; }
AT=$(login "$BOOTSTRAP_ADMIN_EMAIL" "$BOOTSTRAP_ADMIN_PASSWORD")
for r in faculty exam_cell registrar; do api POST /users "$AT" "{\"email\":\"$r@recovery.test\",\"role\":\"$r\",\"password\":\"$UPASS\"}"; done
FT=$(login faculty@recovery.test "$UPASS"); ET=$(login exam_cell@recovery.test "$UPASS"); RT=$(login registrar@recovery.test "$UPASS")
ID1=$(issue); expect "credential issued and valid" "$(verdict "$ID1")" VALID
KEYS_BEFORE=$(active_keys)
expect "four active keys" "$(echo "$KEYS_BEFORE" | python3 -c 'import sys,ast; print(len(ast.literal_eval(sys.stdin.read())))')" 4

echo "== back up the keys"
dc exec -T -e KEY_BACKUP_PASSPHRASE backend ./server key-backup >"$T/keys.acvs" 2>"$T/backup.err"; expect "backup succeeds" "$?" 0
grep -q '"format": "acvs-key-backup"' "$T/keys.acvs" && ok "backup file has the expected format" || bad "backup file format"
grep -q 'backed up 4 active' "$T/backup.err" && ok "backup reports 4 keys" || bad "backup summary: $(cat "$T/backup.err")"
grep -qi 'seed\|private' "$T/keys.acvs" && bad "backup file leaks key material names" || ok "backup file has no plaintext key fields"
KEY_BACKUP_PASSPHRASE=short dc exec -T -e KEY_BACKUP_PASSPHRASE backend ./server key-backup >/dev/null 2>"$T/short.err"
[ $? -ne 0 ] && grep -q 'at least 16' "$T/short.err" && ok "short passphrase refused" || bad "short passphrase accepted"

echo "== lose the ENCRYPTION_KEY"
export ENCRYPTION_KEY=$K2
dc up -d --force-recreate backend >/dev/null 2>&1
wait_exited && ok "backend refuses to start with the wrong key" || bad "backend still running with the wrong key"
dc logs backend 2>&1 | grep -q 'cannot decrypt the stored active signing key' && ok "startup error explains the problem" || bad "startup error message missing"

echo "== restore"
OUT=$(restore --dry-run <"$T/keys.acvs"); expect "dry run succeeds" "$?" 0
echo "$OUT" | grep -q '4 would be restored' && ok "dry run reports 4 keys" || bad "dry run summary: $OUT"
OUT=$(dc run --rm -T -e KEY_BACKUP_PASSPHRASE backend ./server key-backup 2>&1 >/dev/null); [ $? -ne 0 ] && echo "$OUT" | grep -q 'cannot decrypt' && ok "dry run changed nothing" || bad "dry run modified the database"
OUT=$(KEY_BACKUP_PASSPHRASE=wrong-passphrase-123 restore <"$T/keys.acvs"); [ $? -ne 0 ] && echo "$OUT" | grep -q 'wrong passphrase' && ok "wrong passphrase refused" || bad "wrong passphrase: $OUT"
python3 - "$T/keys.acvs" "$T/tampered.acvs" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); c = d["ciphertext"]
d["ciphertext"] = c[:-1] + ("0" if c[-1] != "0" else "1")
json.dump(d, open(sys.argv[2], "w"))
PY
OUT=$(restore <"$T/tampered.acvs"); [ $? -ne 0 ] && ok "tampered backup refused" || bad "tampered backup accepted: $OUT"
OUT=$(restore <"$T/keys.acvs"); expect "restore succeeds" "$?" 0
echo "$OUT" | grep -q '4 restored' && ok "restore reports 4 keys" || bad "restore summary: $OUT"

echo "== service recovers"
dc up -d --force-recreate --wait backend >/dev/null 2>&1 && ok "backend starts under the new key" || bad "backend did not start after restore"
expect "credential signed before the loss still verifies" "$(verdict "$ID1")" VALID
expect "same signing keys as before" "$(active_keys)" "$KEYS_BEFORE"
ID2=$(issue); expect "new credential signs and verifies" "$(verdict "$ID2")" VALID
OUT=$(restore <"$T/keys.acvs"); expect "restore is repeatable" "$?" 0
dc exec -T -e KEY_BACKUP_PASSPHRASE backend ./server key-backup >/dev/null 2>&1; expect "backup works under the new key" "$?" 0

echo "== database lost: rebuild the keys from the backup alone"
dc down -v >/dev/null 2>&1
dc up -d --wait postgres >/dev/null 2>&1
OUT=$(restore <"$T/keys.acvs"); expect "restore into an empty database succeeds" "$?" 0
echo "$OUT" | grep -q '4 inserted' && ok "restore reports 4 inserted keys" || bad "insert summary: $OUT"
dc up -d --wait backend >/dev/null 2>&1 && ok "backend starts on the rebuilt database" || bad "backend did not start"
AT=$(login "$BOOTSTRAP_ADMIN_EMAIL" "$BOOTSTRAP_ADMIN_PASSWORD")
expect "rebuilt keys equal the originals (none regenerated)" "$(active_keys)" "$KEYS_BEFORE"

echo "== a restart must not undo a key revocation"
api GET /keys "$AT"; FKEY=$(echo "$BODY" | j "[k['id'] for k in d['keys'] if k['role']=='faculty' and k['status']=='active'][0]")
api POST "/keys/$FKEY/revoke" "$AT" '{"reason":"recovery test"}'; expect "revoke faculty key" "$CODE" 200
dc up -d --force-recreate --wait backend >/dev/null 2>&1 && ok "backend restarts with a stage key revoked" || bad "backend did not restart"
expect "no replacement key was generated" "$(active_keys | python3 -c 'import sys,ast; print(sum(k.startswith("faculty:") for k in ast.literal_eval(sys.stdin.read())))')" 0
warned=0; for _ in $(seq 1 10); do dc logs backend 2>&1 | grep -q 'no active signing key' && { warned=1; break; }; sleep 1; done # log delivery can lag the health check
[ $warned = 1 ] && ok "restart warns about the missing key" || bad "no warning logged"
api POST /keys/faculty/rotate "$AT"; expect "rotating restores signing" "$CODE" 200
expect "faculty key active again" "$(active_keys | python3 -c 'import sys,ast; print(sum(k.startswith("faculty:") for k in ast.literal_eval(sys.stdin.read())))')" 1

echo
[ $fails -eq 0 ] && echo "ALL RECOVERY CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
