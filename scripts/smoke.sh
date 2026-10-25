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
for t in "$FAC" "$EXC" "$REG" "$ADM" "$AUD"; do [ -n "$t" ] || { echo "FAIL: login ($CODE $BODY)"; [ "$CODE" = 429 ] && echo "      Request limits are counted in the database and survive restarts: wait a minute, or run this against a fresh stack."; exit 1; }; done
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
call GET /ledger/blocks/1/timestamp ""; check "no external timestamp when no authority is configured" 404
call POST /ledger/timestamp "$ADM"; check "timestamping run refused when not configured" 409
call GET /ledger/blocks "$ADM"; expect "block list reports timestamping off" "$(echo "$BODY" | j "d['timestamping']")" None

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

echo "== signed rejection and revocation"
yes() { if [[ "$2" == "$3" ]]; then echo "  ok   $1"; else echo "  FAIL $1: expected '$3' got '$2'"; fails=$((fails+1)); fi; }
TERM_OF() { echo "$BODY" | j "str(d['termination']['kind'])+':'+str(d['termination']['stage'])+':'+str(d['termination']['valid'])"; }
call GET /verify/$ID; yes "revocation is a signed event" "$(TERM_OF)" "revoked:university:True"
yes "reason is read from the signed event" "$(echo "$BODY" | j "d['credential']['revoke_reason']")" "issued in error"
yes "termination check passes" "$(echo "$BODY" | j "d['checks']['termination_ok']")" True
call GET /verify/$ID2; yes "rejection is a signed event" "$(TERM_OF)" "rejected:university:True"
yes "rejected verdict comes from the event" "$(echo "$BODY" | j "d['verdict']")" REJECTED
call POST /credentials/$ID/revoke "$ADM" '{"reason":"again"}'; check "cannot revoke twice" 409
call POST /credentials/$ID2/approve "$ADM"; check "cannot sign a rejected credential" 409
R=$(DBX "UPDATE credentials SET status='issued' WHERE id='$ID'"); [[ "$R" == *"status is final"* ]] && echo "  ok   a revoked status cannot be changed back by SQL" || { echo "  FAIL status editable: $R"; fails=$((fails+1)); }
R=$(DBX "DELETE FROM credential_events WHERE credential_id='$ID'"); [[ "$R" == *"append-only"* ]] && echo "  ok   events cannot be deleted" || { echo "  FAIL event deletable: $R"; fails=$((fails+1)); }

# Attacks by someone who can switch the database triggers off.
NOFINAL="ALTER TABLE credentials DISABLE TRIGGER credentials_final_status;"; FINAL="ALTER TABLE credentials ENABLE TRIGGER credentials_final_status;"
NOEV="ALTER TABLE credential_events DISABLE TRIGGER credential_events_append_only;"; EV="ALTER TABLE credential_events ENABLE TRIGGER credential_events_append_only;"
DBX "$NOFINAL UPDATE credentials SET status='issued' WHERE id='$ID'; $FINAL" >/dev/null
call GET /verify/$ID; yes "un-revoking the status column does not revive the credential" "$(echo "$BODY" | j "d['verdict']")" REVOKED
yes "and the edit is flagged" "$(echo "$BODY" | j "d['checks']['termination_ok']")" False
DBX "UPDATE credentials SET status='revoked' WHERE id='$ID'" >/dev/null
call GET /verify/$ID; yes "status restored, checks pass again" "$(echo "$BODY" | j "d['checks']['termination_ok']")" True

call POST /credentials "$FAC" "$BODY_C"; ID3=$(echo "$BODY" | j "d['id']")
for t in "$EXC" "$REG" "$ADM"; do call POST /credentials/$ID3/approve "$t"; done
call GET /verify/$ID3; yes "a fresh issued credential is VALID" "$(echo "$BODY" | j "d['verdict']")" VALID
DBX "UPDATE credentials SET status='revoked', revoked_at=now(), revoke_reason='forged' WHERE id='$ID3'" >/dev/null
call GET /verify/$ID3; yes "a revoked status with no signed event is INVALID, not trusted" "$(echo "$BODY" | j "d['verdict']")" INVALID
yes "and is flagged" "$(echo "$BODY" | j "d['checks']['termination_ok']")" False
DBX "$NOFINAL UPDATE credentials SET status='issued', revoked_at=NULL, revoke_reason=NULL WHERE id='$ID3'; $FINAL" >/dev/null
call GET /verify/$ID3; yes "restored to VALID" "$(echo "$BODY" | j "d['verdict']")" VALID

DBX "$NOEV UPDATE credential_events SET reason='forged reason' WHERE credential_id='$ID'; $EV" >/dev/null
call GET /verify/$ID; yes "an edited revocation reason breaks its signature" "$(echo "$BODY" | j "d['verdict']")" INVALID
yes "and the event is reported invalid" "$(echo "$BODY" | j "d['termination']['valid']")" False
DBX "$NOEV UPDATE credential_events SET reason='issued in error' WHERE credential_id='$ID'; $EV" >/dev/null
call GET /verify/$ID; yes "reason restored, REVOKED again" "$(echo "$BODY" | j "d['verdict']")" REVOKED

DBX "$NOFINAL UPDATE credentials SET status='pending_university' WHERE id='$ID2'; $FINAL" >/dev/null
call GET /verify/$ID2; yes "a rejected credential stays REJECTED when its status is reset" "$(echo "$BODY" | j "d['verdict']")" REJECTED
call POST /credentials/$ID2/approve "$ADM"; check "and cannot be signed while its status is reset" 409
DBX "UPDATE credentials SET status='rejected' WHERE id='$ID2'" >/dev/null

DBX "$NOEV DELETE FROM credential_events WHERE credential_id='$ID'; $EV" >/dev/null
call GET /verify/$ID; yes "a revoked status whose event was deleted reads as INVALID" "$(echo "$BODY" | j "d['verdict']")" INVALID
docker compose restart backend >/dev/null 2>&1; docker compose up -d --wait >/dev/null 2>&1
call GET /verify/$ID; yes "a restart re-signs the missing event: REVOKED again" "$(echo "$BODY" | j "d['verdict']")" REVOKED
yes "marked as added later" "$(echo "$BODY" | j "d['termination']['legacy']")" True
yes "with a valid signature" "$(echo "$BODY" | j "d['termination']['valid']")" True

echo "== re-issue"
vd() { echo "$BODY" | j "d['verdict']"; }
approve_all() { for t in "$EXC" "$REG" "$ADM"; do call POST /credentials/$1/approve "$t"; done; }
call POST /credentials/$ID3/reissue "$FAC" '{}'; check "a VALID credential cannot be re-issued" 409
call POST /credentials "$FAC" "$BODY_C"; PEND=$(echo "$BODY" | j "d['id']")
call POST /credentials/$PEND/reissue "$FAC" '{}'; check "a PENDING credential cannot be re-issued" 409
call POST /credentials/$ID/reissue "$EXC" '{}'; check "only faculty can re-issue" 403
call POST /credentials/$ID/reissue "$FAC" '{}'; check "a revoked credential is re-issued" 201
NEW1=$(echo "$BODY" | j "d['id']"); yes "response names the credential it replaces" "$(echo "$BODY" | j "d['replaces']")" "$ID"
call GET /verify/$NEW1; yes "the replacement starts PENDING" "$(vd)" PENDING
yes "and points back at the old one" "$(echo "$BODY" | j "d['supersedes']")" "$ID"
yes "with a different content hash" "$(echo "$BODY" | j "d['credential']['credential_hash'] != '$HASH'")" True
call POST /credentials/$ID/reissue "$FAC" '{}'; check "cannot re-issue while a live replacement exists" 409
approve_all $NEW1
call GET /verify/$NEW1; yes "the replacement goes through every stage and is VALID" "$(vd)" VALID
call GET /verify/$ID; yes "the old credential still reads REVOKED" "$(vd)" REVOKED
yes "and points to its replacement" "$(echo "$BODY" | j "d['superseded_by']['id']")" "$NEW1"
yes "which is VALID" "$(echo "$BODY" | j "d['superseded_by']['verdict']")" VALID

call POST /credentials/$ID2/reissue "$FAC" '{"student_name":"Ada Lovelace-King"}'; check "a rejected credential is re-issued with a correction" 201
NEW2=$(echo "$BODY" | j "d['id']")
call GET /credentials/$NEW2 "$FAC"
yes "the corrected field is used" "$(echo "$BODY" | j "d['student_name']")" "Ada Lovelace-King"
yes "other fields are copied" "$(echo "$BODY" | j "d['program']")" "BSc Computer Science"

DBX "UPDATE credentials SET supersedes='$ID' WHERE id='$ID3'" >/dev/null
call GET /verify/$ID3; yes "editing the replaces link breaks the content hash" "$(vd)" INVALID
yes "and the check says so" "$(echo "$BODY" | j "d['checks']['hash_ok']")" False
DBX "UPDATE credentials SET supersedes=NULL WHERE id='$ID3'" >/dev/null
call GET /verify/$ID3; yes "link removed, VALID again" "$(vd)" VALID

call POST /credentials "$FAC" "$BODY_C"; TAMP=$(echo "$BODY" | j "d['id']"); approve_all $TAMP
DBX "UPDATE credentials SET student_name='Mallory' WHERE id='$TAMP'" >/dev/null
call GET /verify/$TAMP; yes "a tampered credential is INVALID" "$(vd)" INVALID
call POST /credentials/$TAMP/reissue "$FAC" '{}'; check "its stored content is not copied" 400
call POST /credentials/$TAMP/reissue "$FAC" '{"student_id":"STU-1","student_name":"Ada Lovelace","program":"BSc Computer Science","graduation_date":"2025-05-15"}'; check "but it can be re-issued with explicit fields" 201

# A stage key is compromised: everything it signed becomes INVALID, and can be replaced.
call GET /keys "$ADM"; EKEY=$(echo "$BODY" | j "[k['id'] for k in d['keys'] if k['role']=='exam_cell' and k['status']=='active'][0]")
call POST /keys/$EKEY/revoke "$ADM" '{"reason":"smoke: compromised"}'; check "revoke the exam cell key" 200
call GET /verify/$ID3; yes "a credential signed by the revoked key reads INVALID" "$(vd)" INVALID
call POST /keys/exam_cell/rotate "$ADM"; check "rotate the exam cell key" 200
call POST /credentials/$ID3/reissue "$FAC" '{}'; check "it is re-issued from its (intact) content" 201
NEW3=$(echo "$BODY" | j "d['id']"); approve_all $NEW3
call GET /verify/$NEW3; yes "the replacement, signed with the new key, is VALID" "$(vd)" VALID
call GET /verify/$ID3; yes "the old one points to the valid replacement" "$(echo "$BODY" | j "d['superseded_by']['verdict']")" VALID
call GET /audit "$ADM"; yes "re-issue is audited" "$(echo "$BODY" | j "any(l['action']=='CREDENTIAL_REISSUED' for l in d['logs'])")" True

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

echo "== bulk import (a body well over the 16 KB limit of every other request)"
ROWS=$(python3 -c '
import json
print(json.dumps({"items": [{"student_id": f"BULK-{i}", "student_name": f"Student Number {i}", "program": "BSc Mathematics", "graduation_date": "2025-05-15", "gpa": "3.9", "honors": "First class"} for i in range(500)]}))')
[ ${#ROWS} -gt 16384 ] && echo "  ok   the import body is ${#ROWS} bytes" || { echo "  FAIL import body too small to test the limit"; fails=$((fails+1)); }
call POST /credentials/bulk "$EXC" "$ROWS"; check "exam cell cannot import" 403
call POST /credentials/bulk "$FAC" "$ROWS"; check "faculty imports the maximum, 500 credentials (3,000 values)" 201
expect "all 500 were created" "$(echo "$BODY" | j "d['created']")" 500
call POST /credentials "$FAC" "{\"student_id\":\"S\",\"student_name\":\"x\",\"program\":\"$(python3 -c 'print("p"*20000)')\",\"graduation_date\":\"2025-05-15\"}"; check "a single credential is still limited to 16 KB" 413

echo "== rate limit"
for i in $(seq 1 15); do call POST /auth/login "" '{"email":"x@y.z","password":"bad"}'; [ "$CODE" = 429 ] && break; done
check "login throttled under repeated attempts" 429

echo
[ $fails -eq 0 ] && echo "ALL CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
