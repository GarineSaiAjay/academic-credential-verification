#!/usr/bin/env bash
# Proves that sealed blocks are anchored to an external RFC 3161 time-stamping authority.
# Usage: scripts/timestamp-test.sh
#
# Runs a throwaway copy of the development stack ("acvsts") plus a throwaway authority
# (deploy/test-tsa.yml) that can be told to answer correctly, with an untrusted key, with garbage, or not at all.
# It publishes the same ports as the main dev stack, so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

T=$(mktemp -d); chmod 755 "$T"
export TSA_DIR="$T"
dc() { docker compose -p acvsts -f docker-compose.yml -f deploy/test-tsa.yml "$@"; }
trap 'dc down -v >/dev/null 2>&1; rm -rf "$T"' EXIT

PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2)
BASE=http://localhost:3000/api/v1
fails=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
# call METHOD PATH [TOKEN] [BODY] -> sets CODE and BODY
call() {
  local args=(-s -o "$T/body" -w '%{http_code}' -X "$1" "$BASE$2" -H 'Content-Type: application/json')
  [ -n "${3:-}" ] && args+=(-H "Authorization: Bearer $3")
  [ "$1" = POST ] && args+=(-H "X-Nonce: $(python3 -c 'import uuid; print(uuid.uuid4())')" -H "X-Timestamp: $(date +%s)")
  [ -n "${4:-}" ] && args+=(-d "$4")
  CODE=$(curl "${args[@]}"); BODY=$(cat "$T/body")
}
login() { call POST /auth/login "" "{\"email\":\"$1@university.edu\",\"password\":\"$PASS\"}"; echo "$BODY" | j "d['token']"; }
issue() { # takes a credential through all four stages and prints its id
  call POST /credentials "$FAC" '{"student_id":"S-1","student_name":"Ada Lovelace","program":"BSc","graduation_date":"2025-05-15"}'
  local id; id=$(echo "$BODY" | j "d['id']")
  for t in "$EXC" "$REG" "$ADM"; do call POST "/credentials/$id/approve" "$t"; done
  echo "$id"
}
mode() { echo "$1" > "$T/mode"; }
wait_stamp() { # height seconds
  for _ in $(seq 1 "$2"); do call GET "/ledger/blocks/$1/timestamp"; [ "$CODE" = 200 ] && return 0; sleep 1; done; return 1
}

echo "== start (stack + test time-stamping authority)"
dc up -d --build --wait >/dev/null 2>&1 && ok "stack and authority healthy" || { bad "stack did not start"; exit 1; }
FAC=$(login faculty); EXC=$(login examcell); REG=$(login registrar); ADM=$(login admin)
[ -n "$FAC$EXC$REG$ADM" ] || { echo "login failed"; exit 1; }
dc logs backend 2>&1 | grep -q 'anchoring sealed blocks' && ok "backend reports timestamping enabled" || bad "no startup message"

echo "== a sealed block gets a trusted timestamp"
ID1=$(issue)
call POST /ledger/seal "$ADM"; expect "seal block 1" "$CODE" 200
wait_stamp 1 30 && ok "block 1 timestamped without any manual step" || bad "block 1 was not timestamped"
expect "server re-verifies the token" "$(echo "$BODY" | j "d['verified']")" True
expect "token is about this block" "$(echo "$BODY" | j "d['imprint']==d['block_hash']")" True
expect "stamped time is recent" "$(echo "$BODY" | j "abs(__import__('time').time()-__import__('datetime').datetime.fromisoformat(d['time'].replace('Z','+00:00')).timestamp())<120")" True
expect "authority recorded" "$(echo "$BODY" | j "d['tsa']")" "http://tsa:8318/tsr"
echo "$BODY" | j "d['serial']" | grep -q . && ok "serial number recorded" || bad "no serial"
call GET /verify/$ID1; expect "credential verify shows the external timestamp" "$(echo "$BODY" | j "d['anchor']['external_timestamp']['imprint_ok']")" True
expect "verdict still VALID" "$(echo "$BODY" | j "d['verdict']")" VALID
call GET /ledger/blocks "$ADM"; expect "block list shows the timestamp" "$(echo "$BODY" | j "d['blocks'][0]['external_timestamp'] is not None")" True
expect "block list says timestamping is on" "$(echo "$BODY" | j "d['timestamping']['url']")" "http://tsa:8318/tsr"
call GET /ledger/verify; expect "chain verification reports the timestamp ok" "$(echo "$BODY" | j "d['blocks'][0]['external_timestamp']")" ok
expect "chain still ok" "$(echo "$BODY" | j "d['ok']")" True

echo "== anyone can verify it with plain openssl, without trusting this server"
curl -s -o "$T/b1.tsq" "$BASE/ledger/blocks/1/timestamp.tsq"; curl -s -o "$T/b1.tsr" "$BASE/ledger/blocks/1/timestamp.tsr"
[ -s "$T/b1.tsq" ] && [ -s "$T/b1.tsr" ] && ok "request and reply downloadable without login" || bad "raw downloads empty"
OUT=$(dc exec -T tsa openssl ts -verify -queryfile /tsa/b1.tsq -in /tsa/b1.tsr -CAfile /tsa/ca.pem 2>&1)
echo "$OUT" | grep -q 'Verification: OK' && ok "openssl verifies against the authority's CA" || bad "openssl: $OUT"
OUT=$(dc exec -T tsa openssl ts -verify -queryfile /tsa/b1.tsq -in /tsa/b1.tsr -CAfile /tsa/evil-ca.pem 2>&1)
echo "$OUT" | grep -q 'Verification: OK' && bad "verified against the WRONG CA" || ok "openssl refuses it under a different CA"
call GET /ledger/blocks/1/timestamp
expect "the request asks for exactly the block's hash" "$(python3 -c "print(open('$T/b1.tsq','rb').read()[24:56].hex())")" "$(echo "$BODY" | j "d['block_hash']")"

echo "== access control"
call POST /ledger/timestamp "$FAC"; expect "faculty cannot trigger timestamping" "$CODE" 403
call POST /ledger/timestamp ""; expect "anonymous cannot trigger timestamping" "$CODE" 401
call GET /ledger/blocks/99/timestamp; expect "unknown block has no timestamp" "$CODE" 404

echo "== the authority misbehaves: the block stays pending, nothing untrusted is stored"
for m in garbage evil down; do
  mode "$m"
  if [ "$m" = garbage ]; then ID2=$(issue); call POST /ledger/seal "$ADM"; expect "seal block 2 while the authority answers garbage" "$CODE" 200; sleep 3; fi
  call POST /ledger/timestamp "$ADM"
  expect "[$m] nothing stamped" "$(echo "$BODY" | j "d['stamped']")" 0
  expect "[$m] failure reported for block 2" "$(echo "$BODY" | j "d['failed'][0]['height']")" 2
  echo "  info [$m] $(echo "$BODY" | j "d['failed'][0]['error']")"
  call GET /ledger/blocks/2/timestamp; expect "[$m] block 2 still has no timestamp" "$CODE" 404
done
mode evil
call POST /ledger/timestamp "$ADM"
echo "$BODY" | j "d['failed'][0]['error']" | grep -q 'rejected by OpenSSL' && ok "a reply signed by an untrusted CA is rejected" || bad "evil reply not rejected: $BODY"
call GET /verify/$ID2; expect "credential in an unstamped block is still VALID" "$(echo "$BODY" | j "d['verdict']")" VALID
expect "and shows no external timestamp yet" "$(echo "$BODY" | j "d['anchor']['external_timestamp']")" None

echo "== recovery: the background retry stamps the pending block by itself"
mode ok
wait_stamp 2 45 && ok "block 2 stamped by the background loop" || bad "block 2 never stamped"
expect "block 2 verified" "$(echo "$BODY" | j "d['verified']")" True

echo "== sealing triggers timestamping immediately"
ID3=$(issue); call POST /ledger/seal "$ADM"; expect "seal block 3" "$CODE" 200
wait_stamp 3 8 && ok "block 3 stamped within seconds of sealing" || bad "block 3 not stamped promptly"
call POST /ledger/timestamp "$ADM"; expect "nothing left to do" "$(echo "$BODY" | j "d['attempted']")" 0

echo "== tampering is detected"
R=$(dc exec -T postgres psql -U acvs -d acvs -qAt -c "UPDATE block_timestamps SET serial='x' WHERE block_height=1" 2>&1)
echo "$R" | grep -q 'append-only' && ok "stored timestamps cannot be edited" || bad "stamp editable: $R"
dc exec -T postgres psql -U acvs -d acvs -qAt -c "ALTER TABLE block_timestamps DISABLE TRIGGER USER; UPDATE block_timestamps SET response = set_byte(response, 100, get_byte(response, 100) # 255) WHERE block_height=1; ALTER TABLE block_timestamps ENABLE TRIGGER USER" >/dev/null 2>&1
call GET /ledger/blocks/1/timestamp
expect "a corrupted token is reported as not verified" "$(echo "$BODY" | j "d['verified']")" False
echo "  info $(echo "$BODY" | j "d['error']")"
dc exec -T postgres psql -U acvs -d acvs -qAt -c "ALTER TABLE block_timestamps DISABLE TRIGGER USER; UPDATE block_timestamps SET imprint = repeat('0', 64) WHERE block_height=2; ALTER TABLE block_timestamps ENABLE TRIGGER USER" >/dev/null 2>&1
call GET /ledger/verify
expect "an imprint that is not the block's hash breaks chain verification" "$(echo "$BODY" | j "d['ok']")" False
expect "and is reported per block" "$(echo "$BODY" | j "d['blocks'][1]['external_timestamp']")" mismatch

echo
[ $fails -eq 0 ] && echo "ALL TIMESTAMP CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
