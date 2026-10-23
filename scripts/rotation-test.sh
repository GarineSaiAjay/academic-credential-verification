#!/usr/bin/env bash
# Proves that ENCRYPTION_KEY can be rotated with no downtime and no loss: add the new key, re-encrypt, drop the old.
# Usage: scripts/rotation-test.sh
#
# Runs a throwaway copy of the development stack ("acvsrot"). It publishes the same ports as the main
# dev stack, so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

T=$(mktemp -d)
dc() { docker compose -p acvsrot "$@"; }
trap 'dc down -v >/dev/null 2>&1; rm -rf "$T"' EXIT

PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2)
BASE=http://localhost:3000/api/v1
BODY_C='{"student_id":"STU-1","student_name":"Ada Lovelace","program":"BSc Computer Science","graduation_date":"2025-05-15"}'
K1=$(openssl rand -hex 32); K2=$(openssl rand -hex 32); K3=$(openssl rand -hex 32)
kid() { python3 -c "import hashlib,sys; print(hashlib.sha256(b'ACVS-KEY-ID-v1'+bytes.fromhex(sys.argv[1])).hexdigest()[:16])" "$1"; }
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
  CODE=$(curl "${args[@]}"); BODY=$(cat "$T/body")
}
login() { call POST /auth/login "" "{\"email\":\"$1@university.edu\",\"password\":\"$PASS\"}"; echo "$BODY" | j "d['token']"; }
DBX() { dc exec -T postgres psql -U acvs -d acvs -qAt -c "$1" 2>&1; }
headers() { DBX "SELECT string_agg(role||':'||encode(substring(private_key_enc from 1 for 10),'hex'), ' ' ORDER BY role, created_at) FROM signing_keys"; }
fingerprint() { DBX "SELECT md5(string_agg(encode(private_key_enc,'hex'), ',' ORDER BY id)) FROM signing_keys"; }
issue() { # takes a new credential through all four stages, prints its id
  call POST /credentials "$FAC" "$BODY_C"; local id; id=$(echo "$BODY" | j "d['id']")
  for t in "$EXC" "$REG" "$ADM"; do call POST /credentials/$id/approve "$t"; done; echo "$id"
}
verdict() { call GET "/verify/$1"; echo "$BODY" | j "d['verdict']"; }
# restart the backend with the given keys; returns non-zero if it does not become healthy
start_with() { export ENCRYPTION_KEY=$1 ENCRYPTION_KEY_PREVIOUS=${2:-}; dc up -d --force-recreate --wait backend >/dev/null 2>&1; }
logs() { dc logs backend 2>&1; }
cli() { dc run --rm -T backend ./server "$@" 2>&1; }

echo "== a normal start"
export SEED_DEMO_PASSWORD=$PASS
start_with "$K1" || { echo "FAIL: stack did not start"; exit 1; }
dc up -d --wait >/dev/null 2>&1
FAC=$(login faculty); EXC=$(login examcell); REG=$(login registrar); ADM=$(login admin)
C1=$(issue); expect "a credential is issued" "$(verdict "$C1")" VALID
ID1=$(kid "$K1"); ID2=$(kid "$K2")
H=$(headers); [ "$(echo "$H" | tr ' ' '\n' | grep -c "ac01$ID1")" = 4 ] && ok "all four keys are sealed under key $ID1 (self-describing header)" || bad "headers: $H"

echo "== data from before the header existed still works"
DBX "UPDATE signing_keys SET private_key_enc = substring(private_key_enc from 11) WHERE role = 'registrar'" >/dev/null
[ "$(DBX "SELECT count(*) FROM signing_keys WHERE role='registrar' AND encode(substring(private_key_enc from 1 for 2),'hex') = 'ac01'")" = 0 ] && ok "registrar key is now in the old layout" || bad "could not strip header"
start_with "$K1" && ok "backend starts with an old-layout key" || bad "backend did not start"
logs | grep -q 'not encrypted under the current ENCRYPTION_KEY' && ok "and warns that a rewrap is due" || bad "no warning about the old layout"
C2=$(issue); expect "it can still sign (the old-layout registrar key)" "$(verdict "$C2")" VALID

echo "== rotating"
start_with "$K2"; rc=$?
[ $rc -ne 0 ] && ok "the new key alone cannot start the server (it cannot read the stored keys)" || bad "backend started without the old key"
logs | grep -q 'ENCRYPTION_KEY_PREVIOUS' && ok "and the error says to keep the old key in ENCRYPTION_KEY_PREVIOUS" || bad "error does not mention ENCRYPTION_KEY_PREVIOUS"
start_with "$K2" "$K1" && ok "with the old key as ENCRYPTION_KEY_PREVIOUS the server starts" || bad "did not start with both keys"
expect "existing credentials still verify" "$(verdict "$C1")" VALID
C3=$(issue); expect "signing keeps working while both keys are loaded" "$(verdict "$C3")" VALID
call POST /keys/faculty/rotate "$ADM"; expect "a key created now is sealed under the NEW key" "$(DBX "SELECT encode(substring(private_key_enc from 3 for 8),'hex') FROM signing_keys WHERE role='faculty' AND status='active'")" "$ID2"
C4=$(issue); expect "and it signs" "$(verdict "$C4")" VALID

echo "== re-encrypting every stored key"
BEFORE=$(fingerprint)
OUT=$(cli key-rewrap --dry-run); echo "$OUT" | grep -q 'dry run, nothing saved; [1-9][0-9]* key(s) would be re-encrypted' && ok "dry run reports what would change" || bad "dry run: $OUT"
expect "and changes nothing" "$(fingerprint)" "$BEFORE"
OUT=$(ENCRYPTION_KEY_PREVIOUS=$K3 cli key-rewrap); echo "$OUT" | grep -q 'cannot decrypt' && ok "without the right old key it refuses" || bad "bad key accepted: $OUT"
expect "and is all-or-nothing: nothing changed" "$(fingerprint)" "$BEFORE"
OUT=$(ENCRYPTION_KEY=$K2 ENCRYPTION_KEY_PREVIOUS=$K1 cli key-rewrap); echo "$OUT" | grep -qE "[1-9][0-9]* key\(s\) re-encrypted under key $ID2" && ok "rewrap re-encrypts them under key $ID2" || bad "rewrap: $OUT"
H=$(headers); [ "$(echo "$H" | tr ' ' '\n' | grep -c "ac01$ID2")" = "$(echo "$H" | wc -w | tr -d " ")" ] && ok "every key, including the old-layout and retired ones, is in the new layout under the new key" || bad "headers after rewrap: $H"
OUT=$(ENCRYPTION_KEY=$K2 ENCRYPTION_KEY_PREVIOUS=$K1 cli key-rewrap); echo "$OUT" | grep -q '^0 key(s) re-encrypted' && ok "running it again changes nothing" || bad "second run: $OUT"

echo "== dropping the old key"
start_with "$K2" && ok "the server starts with only the new key" || bad "did not start with only the new key"
logs | grep -q 'not encrypted under the current ENCRYPTION_KEY' && bad "still warns after the rewrap" || ok "and no longer warns"
expect "old credentials verify" "$(verdict "$C1")" VALID
C5=$(issue); expect "new credentials are issued" "$(verdict "$C5")" VALID
start_with "$K1"; rc=$?
[ $rc -ne 0 ] && ok "the old key no longer opens anything (it can be destroyed)" || bad "the old key still works"
start_with "$K2" || bad "could not restore the new key"
export KEY_BACKUP_PASSPHRASE="rotation-test-passphrase"
OUT=$(dc exec -T -e KEY_BACKUP_PASSPHRASE backend ./server key-backup 2>&1 >/dev/null); echo "$OUT" | grep -q 'backed up 4 active' && ok "key backup works under the new key" || bad "backup: $OUT"

echo "== bad configuration is refused at startup"
start_with "$K2" "$K2"; rc=$?; [ $rc -ne 0 ] && logs | grep -q 'repeats another key' && ok "a previous key equal to the current one" || bad "duplicate accepted"
start_with "$K2" "nothex"; rc=$?; [ $rc -ne 0 ] && logs | grep -q 'must be hex' && ok "a previous key that is not hex" || bad "non-hex accepted"
start_with "$K2" "$K1,$K3,$(openssl rand -hex 32),$(openssl rand -hex 32),$(openssl rand -hex 32)"; rc=$?; [ $rc -ne 0 ] && logs | grep -q 'at most 4' && ok "more than four previous keys" || bad "too many accepted"
start_with "$K2" "$K1, $K3"; rc=$?; [ $rc -eq 0 ] && ok "a comma-separated list with spaces is fine" || bad "list rejected"

echo
[ $fails -eq 0 ] && echo "ALL ROTATION CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
