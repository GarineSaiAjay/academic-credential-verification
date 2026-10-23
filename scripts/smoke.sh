#!/usr/bin/env bash
# End-to-end test against a running stack. Usage: scripts/smoke.sh [base_url]
# Needs: curl, python3, and docker compose (only for the DB tamper step).
set -uo pipefail
cd "$(dirname "$0")/.."
BASE="${1:-http://localhost:8000}/api/v1"
PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2)
fails=0

j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
nonce() { python3 -c "import uuid; print(uuid.uuid4())"; }
# call METHOD PATH TOKEN [BODY] -> prints "STATUS BODY"
call() {
  local m=$1 p=$2 t=${3:-} b=${4:-}
  local args=(-s -o /tmp/acvs_body -w '%{http_code}' -X "$m" "$BASE$p" -H 'Content-Type: application/json')
  [ -n "$t" ] && args+=(-H "Authorization: Bearer $t")
  [ "$m" = POST ] && [ "${NONCE:-auto}" = auto ] && args+=(-H "X-Nonce: $(nonce)" -H "X-Timestamp: $(date +%s)")
  [ -n "$b" ] && args+=(-d "$b")
  CODE=$(curl "${args[@]}"); BODY=$(cat /tmp/acvs_body)
}
check() { # name expected_code
  if [ "$CODE" = "$2" ]; then echo "  ok   $1 ($CODE)"; else echo "  FAIL $1: expected $2 got $CODE: $BODY"; fails=$((fails+1)); fi
}
expect() { # name actual expected
  if [ "$2" = "$3" ]; then echo "  ok   $1 = $3"; else echo "  FAIL $1: expected '$3' got '$2'"; fails=$((fails+1)); fi
}
login() { call POST /auth/login "" "{\"email\":\"$1@university.edu\",\"password\":\"$PASS\"}"; echo "$BODY" | j "d.get('token','')"; }

echo "== login"
FAC=$(login faculty); EXC=$(login examcell); REG=$(login registrar); ADM=$(login admin); AUD=$(login auditor)
for t in "$FAC" "$EXC" "$REG" "$ADM" "$AUD"; do [ -n "$t" ] || { echo "FAIL: login"; exit 1; }; done
call POST /auth/login "" '{"email":"faculty@university.edu","password":"wrong"}'; check "bad password rejected" 401
call GET /credentials ""; check "no token rejected" 401
call GET /credentials "garbage"; check "bad token rejected" 401

echo "== workflow"
BODY_C='{"student_id":"STU-1","student_name":"Ada Lovelace","program":"BSc Computer Science","graduation_date":"2025-05-15","gpa":"3.9","honors":"Cum Laude"}'
call POST /credentials "$EXC" "$BODY_C"; check "exam cell cannot create" 403
call POST /credentials "$FAC" '{"student_id":"","student_name":"x","program":"x","graduation_date":"2025-05-15"}'; check "validation rejects empty id" 400
call POST /credentials "$FAC" '{"student_id":"S","student_name":"x","program":"x","graduation_date":"15/05/2025"}'; check "validation rejects bad date" 400
call POST /credentials "$FAC" "$BODY_C"; check "faculty creates + signs" 201
ID=$(echo "$BODY" | j "d['id']"); HASH=$(echo "$BODY" | j "d['credential_hash']")
call POST /credentials/$ID/approve "$FAC"; check "faculty cannot self-approve later stage" 409
call POST /credentials/$ID/approve "$REG"; check "registrar cannot skip exam cell" 409
call POST /credentials/$ID/approve "$EXC"; check "exam cell signs" 200
call POST /credentials/$ID/approve "$EXC"; check "exam cell cannot sign twice" 409
call POST /credentials/$ID/approve "$REG"; check "registrar signs" 200
call GET /verify/$ID; expect "verdict while pending" "$(echo "$BODY" | j "d['verdict']")" PENDING
call POST /credentials/$ID/approve "$ADM"; check "university signs -> issued" 200

echo "== public verification"
call GET "/verify/$ID?h=${HASH:0:16}"; check "public verify (no auth)" 200
expect "verdict" "$(echo "$BODY" | j "d['verdict']")" VALID
expect "signature count" "$(echo "$BODY" | j "len(d['signatures'])")" 4
expect "qr hash match" "$(echo "$BODY" | j "d['qr_hash_match']")" True
call GET "/verify/$ID?h=deadbeefdeadbeef"; expect "forged qr hash detected" "$(echo "$BODY" | j "d['qr_hash_match']")" False
curl -s -o /tmp/acvs_qr.png -w '%{content_type}' "$BASE/credentials/$ID/qr" | grep -q image/png && echo "  ok   qr png served" || { echo "  FAIL qr"; fails=$((fails+1)); }

echo "== ledger"
call POST /ledger/seal "$FAC"; check "faculty cannot seal" 403
call POST /ledger/seal "$ADM"; check "admin seals block" 200
call POST /ledger/seal "$ADM"; check "nothing left to seal" 409
call GET /verify/$ID; expect "anchored + proof ok" "$(echo "$BODY" | j "d['anchor']['ok']")" True
call GET /ledger/verify; expect "chain ok" "$(echo "$BODY" | j "d['ok']")" True

echo "== security"
call POST /credentials/$ID/revoke "$FAC" '{"reason":"nope"}'; check "faculty cannot revoke" 403
NONCE=fixed; H=(-H "Authorization: Bearer $EXC" -H "Content-Type: application/json")
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/credentials" "${H[@]}" -d "$BODY_C"); expect "missing nonce rejected" "$CODE" 400
N=$(nonce); T=$(date +%s)
curl -s -o /dev/null -X POST "$BASE/credentials" -H "Authorization: Bearer $FAC" -H "X-Nonce: $N" -H "X-Timestamp: $T" -H 'Content-Type: application/json' -d "$BODY_C"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/credentials" -H "Authorization: Bearer $FAC" -H "X-Nonce: $N" -H "X-Timestamp: $T" -H 'Content-Type: application/json' -d "$BODY_C"); expect "replayed request rejected" "$CODE" 409
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/credentials" -H "Authorization: Bearer $FAC" -H "X-Nonce: $(nonce)" -H "X-Timestamp: $(( $(date +%s) - 600 ))" -H 'Content-Type: application/json' -d "$BODY_C"); expect "stale timestamp rejected" "$CODE" 400
NONCE=auto
call GET /audit "$FAC"; check "faculty cannot read audit" 403
call GET /audit "$AUD"; check "auditor reads audit" 200
call GET /keys "$AUD"; check "auditor lists keys" 200
call POST /keys/university/rotate "$AUD"; check "auditor cannot rotate keys" 403

echo "== tamper detection (direct database edit)"
DBX() { docker compose exec -T postgres psql -U acvs -d acvs -qAt -c "$1" 2>&1; }
DBX "UPDATE credentials SET student_name='Mallory' WHERE id='$ID'" >/dev/null
call GET /verify/$ID; expect "edited name -> INVALID" "$(echo "$BODY" | j "d['verdict']")" INVALID
DBX "UPDATE credentials SET student_name='Ada Lovelace' WHERE id='$ID'" >/dev/null
call GET /verify/$ID; expect "restored -> VALID" "$(echo "$BODY" | j "d['verdict']")" VALID
R=$(DBX "UPDATE approvals SET signature='00' WHERE credential_id='$ID'"); echo "$R" | grep -q 'append-only' && echo "  ok   approvals are append-only" || { echo "  FAIL approvals mutable: $R"; fails=$((fails+1)); }

echo "== key revocation + rotation"
call GET /keys "$ADM"; UKEY=$(echo "$BODY" | j "[k['id'] for k in d['keys'] if k['role']=='registrar' and k['status']=='active'][0]")
call POST /keys/$UKEY/revoke "$ADM" '{"reason":"suspected compromise"}'; check "revoke registrar key" 200
call GET /verify/$ID; expect "revoked key invalidates credential" "$(echo "$BODY" | j "d['verdict']")" INVALID
call POST /keys/registrar/rotate "$ADM"; check "rotate registrar key" 200
call POST /credentials "$FAC" "$BODY_C"; ID2=$(echo "$BODY" | j "d['id']"); check "new credential" 201
call POST /credentials/$ID2/approve "$EXC"; call POST /credentials/$ID2/approve "$REG"; check "registrar signs with rotated key" 200
call POST /credentials/$ID2/reject "$ADM" '{"reason":"data mismatch"}'; check "admin rejects" 200
call GET /verify/$ID2; expect "rejected verdict" "$(echo "$BODY" | j "d['verdict']")" REJECTED
call POST /credentials/$ID/revoke "$ADM" '{"reason":"issued in error"}'; check "admin revokes issued" 200
call GET /verify/$ID; expect "revoked verdict" "$(echo "$BODY" | j "d['verdict']")" REVOKED

echo "== user management"
# Budget: the login limiter allows 10/min per IP and 6 logins are already used, so this section makes 4.
UEMAIL="smoke-$RANDOM$RANDOM@university.edu"; P1="smoke-pass-one-1"; P2="smoke-pass-two-2"; P3="smoke-pass-three-3"
call GET /users "$FAC"; check "faculty cannot list users" 403
call GET /users "$AUD"; check "auditor cannot list users" 403
call POST /users "$FAC" "{\"email\":\"$UEMAIL\",\"role\":\"auditor\",\"password\":\"$P1\"}"; check "faculty cannot create users" 403
call GET /users "$ADM"; check "admin lists users" 200
call POST /users "$ADM" "{\"email\":\"not-an-email\",\"role\":\"auditor\",\"password\":\"$P1\"}"; check "invalid email rejected" 400
call POST /users "$ADM" "{\"email\":\"$UEMAIL\",\"role\":\"superuser\",\"password\":\"$P1\"}"; check "unknown role rejected" 400
call POST /users "$ADM" "{\"email\":\"$UEMAIL\",\"role\":\"auditor\",\"password\":\"short\"}"; check "short password rejected" 400
call POST /users "$ADM" "{\"email\":\"$UEMAIL\",\"role\":\"auditor\",\"password\":\"$P1\"}"; check "admin creates user" 201
UID_=$(echo "$BODY" | j "d['id']")
call POST /users "$ADM" "{\"email\":\"$UEMAIL\",\"role\":\"auditor\",\"password\":\"$P1\"}"; check "duplicate email rejected" 409
call POST /auth/login "" "{\"email\":\"$UEMAIL\",\"password\":\"$P1\"}"; check "new user logs in" 200
T1=$(echo "$BODY" | j "d['token']")
call GET /auth/me "$T1"; expect "new user role" "$(echo "$BODY" | j "d['role']")" auditor

call POST /users/$UID_/role "$FAC" '{"role":"registrar"}'; check "faculty cannot change roles" 403
call POST /users/$UID_/role "$ADM" '{"role":"nonsense"}'; check "role change rejects unknown role" 400
call POST /users/$UID_/role "$ADM" '{"role":"exam_cell"}'; check "admin changes role" 200
call GET /auth/me "$T1"; expect "role change is immediate" "$(echo "$BODY" | j "d['role']")" exam_cell
call GET /auth/me "$ADM"; ADMID=$(echo "$BODY" | j "d['id']")
call POST /users/$ADMID/role "$ADM" '{"role":"auditor"}'; check "admin cannot demote self" 409
call POST /users/$ADMID/active "$ADM" '{"active":false}'; check "admin cannot deactivate self" 409
call POST /users/$ADMID/password "$ADM" "{\"password\":\"$P3\"}"; check "admin cannot reset own password here" 400

call POST /auth/password "$T1" "{\"current_password\":\"wrong-password-xx\",\"new_password\":\"$P2\"}"; check "change password: wrong current rejected" 400
call POST /auth/password "$T1" "{\"current_password\":\"$P1\",\"new_password\":\"tiny\"}"; check "change password: short new rejected" 400
call POST /auth/password "$T1" "{\"current_password\":\"$P1\",\"new_password\":\"$P2\"}"; check "user changes own password" 200
call GET /auth/me "$T1"; check "current session survives password change" 200

call POST /users/$UID_/active "$ADM" '{"active":false}'; check "admin deactivates user" 200
call GET /auth/me "$T1"; check "deactivated user's token stops working" 401
call POST /auth/login "" "{\"email\":\"$UEMAIL\",\"password\":\"$P2\"}"; check "deactivated user cannot log in" 401
call POST /users/$UID_/active "$ADM" '{"active":true}'; check "admin reactivates user" 200
call POST /users/$UID_/password "$ADM" '{"password":"short"}'; check "reset rejects short password" 400
call POST /users/$UID_/password "$ADM" "{\"password\":\"$P3\"}"; check "admin resets password" 200
call POST /auth/login "" "{\"email\":\"$UEMAIL\",\"password\":\"$P2\"}"; check "old password no longer works" 401
call POST /auth/login "" "{\"email\":\"$UEMAIL\",\"password\":\"$P3\"}"; check "new password works" 200
T2=$(echo "$BODY" | j "d['token']")
call GET /auth/me "$T2"; check "reset user is signed in" 200
call GET /audit "$ADM"
for a in USER_CREATED USER_ROLE_CHANGED USER_DEACTIVATED USER_ACTIVATED USER_PASSWORD_RESET PASSWORD_CHANGED; do
  expect "audit has $a" "$(echo "$BODY" | j "any(l['action']=='$a' and '$UEMAIL' in (l['details'] or {}).get('email','$UEMAIL') for l in d['logs'])")" True
done
expect "audit never stores passwords" "$(echo "$BODY" | grep -c -e "$P1" -e "$P2" -e "$P3")" 0
call POST /users/$UID_/active "$ADM" '{"active":false}'; check "cleanup: deactivate smoke user" 200

echo "== container hardening (backend)"
BX() { docker compose exec -T backend sh -c "$1" 2>&1; }
expect "backend runs as an unprivileged user" "$(BX 'id -u' | tr -d '\r')" 10001
expect "backend has no effective capabilities" "$(BX "grep '^CapEff' /proc/self/status" | awk '{print $2}')" 0000000000000000
expect "backend cannot gain privileges" "$(BX "grep '^NoNewPrivs' /proc/self/status" | awk '{print $2}')" 1
[[ "$(BX 'touch /probe')" == *"Read-only file system"* ]] && echo "  ok   root filesystem is read-only" || { echo "  FAIL root filesystem is writable"; fails=$((fails+1)); }
[[ "$(BX 'touch /app/probe')" == *"Read-only file system"* ]] && echo "  ok   application directory is read-only" || { echo "  FAIL application directory is writable"; fails=$((fails+1)); }
BX 'touch /tmp/probe && rm /tmp/probe' >/dev/null && echo "  ok   /tmp is writable scratch space" || { echo "  FAIL /tmp not writable"; fails=$((fails+1)); }

echo "== rate limit"
for i in $(seq 1 15); do call POST /auth/login "" '{"email":"x@y.z","password":"bad"}'; [ "$CODE" = 429 ] && break; done
check "login throttled under repeated attempts" 429

echo
[ $fails -eq 0 ] && echo "ALL CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
