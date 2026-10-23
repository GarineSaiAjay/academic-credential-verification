#!/usr/bin/env bash
# Proves that approvals can carry a person's own signature (a WebAuthn passkey / security key), that forgeries
# are refused, and that the policy "every approval needs one" is enforced.
# Usage: scripts/personal-sig-test.sh            (development stack)
#        MODE=prod scripts/personal-sig-test.sh   (production stack: TLS + WAF; needs host ports 80 and 443 free)
#
# Runs a throwaway copy of the stack ("acvspk"). A software authenticator
# (scripts/webauthn_sim.py, built on openssl) plays the people's security keys. It publishes the same ports
# as the main dev stack, so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

T=$(mktemp -d)
SIM="python3 scripts/webauthn_sim.py"
dc() { docker compose -p acvspk "$@"; }
trap 'dc down -v >/dev/null 2>&1; rm -rf "$T"' EXIT
export REQUIRE_PERSONAL_SIGNATURES=false

PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2)
BASE=http://localhost:3000/api/v1
ORIGIN=http://localhost:3000; RP=localhost
if [ "${MODE:-dev}" = prod ]; then
  export COMPOSE_FILE=docker-compose.prod.yml:deploy/test-seed.yml DOMAIN=localhost BOOTSTRAP_ADMIN_EMAIL= BOOTSTRAP_ADMIN_PASSWORD= SEED_DEMO_PASSWORD=$PASS
  BASE=https://localhost/api/v1; ORIGIN=https://localhost
fi
BODY_C='{"student_id":"STU-1","student_name":"Ada Lovelace","program":"BSc Computer Science","graduation_date":"2025-05-15"}'
fails=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
call() { # METHOD PATH [TOKEN] [BODY] -> CODE, BODY
  local args=(-s -o "$T/body" -w '%{http_code}' -X "$1" "$BASE$2" -H 'Content-Type: application/json')
  [ -n "${3:-}" ] && args+=(-H "Authorization: Bearer $3")
  [ "$1" = POST ] && args+=(-H "X-Nonce: $(python3 -c 'import uuid; print(uuid.uuid4())')" -H "X-Timestamp: $(date +%s)")
  [ -n "${4:-}" ] && args+=(-d "$4")
  CODE=$(curl "${args[@]}"); BODY=$(cat "$T/body")
}
login() { call POST /auth/login "" "{\"email\":\"$1@university.edu\",\"password\":\"$PASS\"}"; echo "$BODY" | j "d['token']"; }
DBX() { dc exec -T postgres psql -U acvs -d acvs -qAt -c "$1" 2>&1; }
status_of() { call GET "/credentials/$1" "$ADM"; echo "$BODY" | j "d['status']"; }
# register NAME TOKEN [AUTHKEY]: make a software key and register it for the logged-in user. If the account
# already has a key, AUTHKEY (an existing software key) must approve the new one.
register() {
  $SIM new "$T" "$1" > "$T/$1.info"
  call POST /me/keys/options "$2"; [ "$CODE" = 200 ] || return 0
  local cid chal auth=""; cid=$(echo "$BODY" | j "d['challenge_id']"); chal=$(echo "$BODY" | j "d['challenge']")
  [ -n "${3:-}" ] && auth=",\"authorization\":$($SIM get "$T" "$3" "$chal" "$RP" "$ORIGIN")"
  local cd; cd=$($SIM create "$T" "$1" "$chal" "$ORIGIN")
  call POST /me/keys "$2" "{\"challenge_id\":\"$cid\",\"credential_id\":\"$(j "d['credential_id']" < "$T/$1.info")\",\"public_key\":\"$(j "d['public_key']" < "$T/$1.info")\",\"client_data_json\":\"$cd\",\"label\":\"$1 key\"$auth}"
}
challenge_of() { $SIM challenge "$1" "$2" "$3"; }          # id stage hash
assertion() { $SIM get "$T" "$1" "$2" "$RP" "$ORIGIN" "${@:3}"; }  # key challenge [opts]
new_cred() { call POST /credentials "$FAC" "$BODY_C"; NEWID=$(echo "$BODY" | j "d['id']"); NEWHASH=$(echo "$BODY" | j "d['credential_hash']"); }
approve_with() { # id token key stage [opts]  -> CODE
  local chal a; chal=$(challenge_of "$1" "$4" "$NEWHASH"); a=$(assertion "$3" "$chal" "${@:5}")
  call POST "/credentials/$1/approve" "$2" "{\"webauthn\":$a}"
}

echo "== start (personal signatures optional)"
dc up -d --build --wait >/dev/null 2>&1 && ok "stack healthy" || { bad "stack did not start"; exit 1; }
if [ "${MODE:-dev}" = prod ]; then
  for _ in $(seq 1 30); do dc cp edge:/data/caddy/pki/authorities/local/root.crt "$T/root.crt" >/dev/null 2>&1 && break; sleep 1; done
  export CURL_CA_BUNDLE="$T/root.crt"; ok "running through TLS and the WAF"
fi
FAC=$(login faculty); EXC=$(login examcell); REG=$(login registrar); ADM=$(login admin)
[ -n "$FAC$EXC$REG$ADM" ] || { echo "login failed"; exit 1; }

echo "== registering personal keys"
register fac "$FAC"; expect "faculty registers a key" "$CODE" 201
register exc "$EXC"; expect "exam cell registers a key" "$CODE" 201
register reg "$REG"; expect "registrar registers a key" "$CODE" 201
register adm "$ADM"; expect "admin registers a key" "$CODE" 201
call GET /me/keys "$EXC"; expect "the key is listed as active" "$(echo "$BODY" | j "d['keys'][0]['status']")" active
echo "$BODY" | grep -qi 'public_key\|private' && bad "key listing exposes key material" || ok "key listing shows no key material"
call POST /me/keys/options "$EXC"; C1=$(echo "$BODY" | j "d['challenge_id']"); H1=$(echo "$BODY" | j "d['challenge']")
$SIM new "$T" x1 >"$T/x1.info"; X1=$(j "d['credential_id']" <"$T/x1.info"); XP1=$(j "d['public_key']" <"$T/x1.info")
reg_body() { echo "{\"challenge_id\":\"$C1\",\"credential_id\":\"$X1\",\"public_key\":\"$XP1\",\"client_data_json\":\"$1\",\"label\":\"x\"}"; }
call POST /me/keys "$EXC" "$(reg_body "$($SIM create "$T" x1 "$H1" "https://evil.example")")"; expect "registration from another origin refused" "$CODE" 400
call POST /me/keys/options "$EXC"; C1=$(echo "$BODY" | j "d['challenge_id']"); H1=$(echo "$BODY" | j "d['challenge']")
call POST /me/keys "$EXC" "$(reg_body "$($SIM create "$T" x1 "$($SIM challenge a b c)" "$ORIGIN")")"; expect "registration with the wrong challenge refused" "$CODE" 400
call POST /me/keys "$EXC" "$(reg_body "$($SIM create "$T" x1 "$H1" "$ORIGIN")")"; expect "a challenge is single-use" "$CODE" 400
call POST /me/keys/options "$EXC"; C1=$(echo "$BODY" | j "d['challenge_id']"); H1=$(echo "$BODY" | j "d['challenge']")
call POST /me/keys "$EXC" "{\"challenge_id\":\"$C1\",\"credential_id\":\"$X1\",\"public_key\":\"AAAA\",\"client_data_json\":\"$($SIM create "$T" x1 "$H1" "$ORIGIN")\",\"label\":\"x\"}"; expect "a malformed public key is refused" "$CODE" 400
call POST /me/keys/options "$REG"; C1=$(echo "$BODY" | j "d['challenge_id']"); H1=$(echo "$BODY" | j "d['challenge']")
call POST /me/keys "$REG" "{\"challenge_id\":\"$C1\",\"credential_id\":\"$(j "d['credential_id']" < "$T/exc.info")\",\"public_key\":\"$(j "d['public_key']" < "$T/exc.info")\",\"client_data_json\":\"$($SIM create "$T" exc "$H1" "$ORIGIN")\",\"label\":\"stolen\"}"; expect "the same authenticator cannot be registered twice" "$CODE" 409
call POST /me/keys/options "$EXC"; C1=$(echo "$BODY" | j "d['challenge_id']"); H1=$(echo "$BODY" | j "d['challenge']")
call POST /me/keys "$REG" "{\"challenge_id\":\"$C1\",\"credential_id\":\"$X1\",\"public_key\":\"$XP1\",\"client_data_json\":\"$($SIM create "$T" x1 "$H1" "$ORIGIN")\",\"label\":\"x\"}"; expect "another user's challenge cannot be used" "$CODE" 400

echo "== an approval with a personal signature"
new_cred; ID1=$NEWID; H=$NEWHASH
call POST /credentials/$ID1/approve "$EXC" ""; expect "approving without one still works while the policy is off" "$CODE" 200
new_cred; ID=$NEWID; H=$NEWHASH
call GET /credentials/$ID1 "$FAC"; expect "the approval was recorded" "$(echo "$BODY" | j "d['status']")" pending_registrar
chal=$(challenge_of "$ID" exam_cell "$H"); call GET /credentials/$ID/personal-challenge "$EXC"
expect "the server's challenge is the SHA-256 of the approval message" "$(echo "$BODY" | j "d['challenge']")" "$chal"
expect "and says what is being signed" "$(echo "$BODY" | j "d['purpose']+':'+d['stage']")" "approve:exam_cell"
expect "and names the keys to use" "$(echo "$BODY" | j "len(d['allow'])")" 1
approve_with $ID "$EXC" exc exam_cell; expect "exam cell approves with a security-key signature" "$CODE" 200
approve_with $ID "$REG" reg registrar; expect "registrar approves with a security-key signature" "$CODE" 200
approve_with $ID "$ADM" adm university; expect "admin approves with a security-key signature" "$CODE" 200
curl -s "$BASE/verify/$ID" > "$T/v.json"
expect "the credential is VALID" "$(j "d['verdict']" < "$T/v.json")" VALID
expect "faculty (created without one) has no personal signature" "$(j "d['signatures'][0]['personal']" < "$T/v.json")" None
expect "exam cell's personal signature verifies" "$(j "d['signatures'][1]['personal']['valid']" < "$T/v.json")" True
expect "personal signature check passes" "$(j "d['checks']['personal_signatures_ok']" < "$T/v.json")" True
expect "the public view names no person" "$(grep -c 'university.edu' "$T/v.json")" 0
call GET /credentials/$ID "$ADM"; expect "signed-in staff can see who approved" "$(echo "$BODY" | j "d['approvers']['exam_cell']")" "examcell@university.edu"

echo "== faculty adds a personal signature to their own approval"
chal=$(challenge_of "$ID" faculty "$H"); a=$(assertion fac "$chal")
call GET /credentials/$ID/personal-challenge "$FAC"; expect "the server offers a countersign" "$(echo "$BODY" | j "d['purpose']+':'+d['stage']")" "countersign:faculty"
call POST /credentials/$ID/countersign "$EXC" "{\"webauthn\":$a}"; expect "someone else cannot countersign it" "$CODE" 409
call POST /credentials/$ID/countersign "$FAC" "{\"webauthn\":$a}"; expect "faculty countersigns their approval" "$CODE" 200
call POST /credentials/$ID/countersign "$FAC" "{\"webauthn\":$(assertion fac "$chal")}"; expect "it can only be done once" "$CODE" 409
call GET /credentials/$ID/personal-challenge "$FAC"; expect "nothing is left to sign" "$CODE" 404

echo "== anyone can verify a personal signature without trusting the server"
curl -s "$BASE/verify/$ID" > "$T/v.json"
OUT=$($SIM check "$T/v.json" 2>&1); expect "openssl verifies every personal signature" "$OUT" "independently verified 4 personal signature(s)"

echo "== forgeries are refused (and the credential is left untouched)"
negative() { # name expected-code opts...
  new_cred; local nid=$NEWID nh=$NEWHASH; NEWHASH=$nh
  approve_with "$nid" "$EXC" exc exam_cell "${@:3}"
  [ "$CODE" = "$2" ] && [ "$(status_of "$nid")" = pending_exam_cell ] && ok "$1" || bad "$1 (got $CODE, status $(status_of "$nid"))"
}
negative "a tampered signature" 400 --tamper sig
negative "tampered authenticator data" 400 --tamper auth
negative "tampered client data" 400 --tamper client
negative "a signature for another site" 400 --rp-override evil.example
negative "a signature for another origin" 400 --origin-override https://evil.example
negative "a signature over a different challenge" 400 --challenge-override "$($SIM challenge a b c)"
negative "no user verification (PIN / biometric)" 400 --flags 0x01
negative "no user presence" 400 --flags 0x04
negative "a replayed counter (cloned key)" 409 --counter 1
new_cred; approve_with $NEWID "$EXC" reg exam_cell; expect "someone else's key" "$CODE" 400
new_cred; call POST /credentials/$NEWID/approve "$EXC" "{\"webauthn\":{\"credential_id\":\"nope\"}}"; expect "an incomplete assertion" "$CODE" 400
new_cred; call POST /credentials/$NEWID/approve "$EXC" "not json"; expect "a malformed body" "$CODE" 400

echo "== adding a key needs an existing key's approval (a stolen password is not enough)"
register exc2 "$EXC"; expect "a login alone cannot add a key to an account that has one" "$CODE" 409
register exc2 "$EXC" reg; expect "nor can another person's key approve it" "$CODE" 400
register exc2 "$EXC" exc; expect "the account's own key can approve a new one" "$CODE" 201
AUD=$(login auditor)
register aud "$AUD"; expect "a first key needs only a login (unless REQUIRE_ADMIN_ENROLLMENT)" "$CODE" 201
call GET /me/keys "$AUD"; AUDKEY=$(echo "$BODY" | j "d['keys'][0]['id']")
call POST /user-keys/$AUDKEY/retire "$AUD"; expect "an attacker could retire the only key..." "$CODE" 200
register aud2 "$AUD"; expect "...but with no active key a login is no longer enough to add one" "$CODE" 409
call GET /auth/me "$AUD"; AUDID=$(echo "$BODY" | j "d['id']")
call POST /users/$AUDID/keys/enroll "$AUD"; expect "a user cannot open their own enrolment window" "$CODE" 403
call POST /users/$AUDID/keys/enroll "$ADM"; expect "an administrator can" "$CODE" 200
register aud2 "$AUD"; expect "then the key can be enrolled" "$CODE" 201
register aud3 "$AUD"; expect "the window was single-use (now a key must approve)" "$CODE" 409
expect "the window is cleared" "$(DBX "SELECT key_enroll_until IS NULL FROM users WHERE id='$AUDID'")" t

echo "== key lifecycle"
call GET /me/keys "$EXC"; KEY1=$(echo "$BODY" | j "d['keys'][0]['id']"); KEY2=$(echo "$BODY" | j "d['keys'][1]['id']")
call POST /user-keys/$KEY1/retire "$REG"; expect "only the owner can retire a key" "$CODE" 404
call POST /user-keys/$KEY1/retire "$EXC"; expect "the owner retires the first key" "$CODE" 200
new_cred; approve_with $NEWID "$EXC" exc exam_cell; expect "a retired key can no longer sign" "$CODE" 409
curl -s "$BASE/verify/$ID" > "$T/v.json"; expect "but what it signed earlier stays valid" "$(j "d['verdict']" < "$T/v.json")" VALID
new_cred; approve_with $NEWID "$EXC" exc2 exam_cell; expect "the new key signs" "$CODE" 200
R=$(DBX "UPDATE user_keys SET status='active' WHERE id='$KEY1'"); [[ "$R" == *"cannot become"* ]] && ok "a retired key cannot be reactivated" || bad "reactivation allowed: $R"
R=$(DBX "UPDATE user_keys SET public_key='\\x00' WHERE id='$KEY2'"); [[ "$R" == *"cannot change"* ]] && ok "key material cannot be swapped" || bad "key swappable: $R"
R=$(DBX "DELETE FROM approval_countersigs"); [[ "$R" == *"append-only"* ]] && ok "countersignatures cannot be deleted" || bad "deletable: $R"
call GET /users/$(call GET /auth/me "$EXC"; echo "$BODY" | j "d['id']")/keys "$ADM"; expect "an admin can list a user's keys" "$CODE" 200
call GET /users/00000000-0000-0000-0000-000000000000/keys "$FAC"; expect "faculty cannot" "$CODE" 403

echo "== tampering with a stored countersignature"
DBX "ALTER TABLE approval_countersigs DISABLE TRIGGER approval_countersigs_append_only; UPDATE approval_countersigs SET signature = set_byte(signature, 20, get_byte(signature, 20) # 255) WHERE approval_id = (SELECT id FROM approvals WHERE credential_id='$ID' AND role='registrar'); ALTER TABLE approval_countersigs ENABLE TRIGGER approval_countersigs_append_only" >/dev/null
curl -s "$BASE/verify/$ID" > "$T/v.json"
expect "a corrupted personal signature makes the credential INVALID" "$(j "d['verdict']" < "$T/v.json")" INVALID
expect "and the personal check fails" "$(j "d['checks']['personal_signatures_ok']" < "$T/v.json")" False
DBX "ALTER TABLE approval_countersigs DISABLE TRIGGER approval_countersigs_append_only; UPDATE approval_countersigs SET signature = set_byte(signature, 20, get_byte(signature, 20) # 255) WHERE approval_id = (SELECT id FROM approvals WHERE credential_id='$ID' AND role='registrar'); ALTER TABLE approval_countersigs ENABLE TRIGGER approval_countersigs_append_only" >/dev/null
curl -s "$BASE/verify/$ID" > "$T/v.json"; expect "restored, VALID again" "$(j "d['verdict']" < "$T/v.json")" VALID

echo "== a compromised key invalidates what it signed"
call POST /user-keys/$KEY2/revoke "$REG" '{"reason":"not mine"}'; expect "another user cannot revoke it" "$CODE" 404
call GET /me/keys "$REG"; REGKEY=$(echo "$BODY" | j "d['keys'][0]['id']")
call POST /user-keys/$REGKEY/revoke "$EXC" '{"reason":"stolen"}'; expect "nor can a different staff member" "$CODE" 404
call POST /user-keys/$REGKEY/revoke "$REG" '{"reason":"laptop stolen"}'; expect "the owner revokes the registrar key" "$CODE" 200
curl -s "$BASE/verify/$ID" > "$T/v.json"
expect "a credential carrying its signature is INVALID" "$(j "d['verdict']" < "$T/v.json")" INVALID
expect "reported against the right signature" "$(j "d['signatures'][2]['personal']['key_status']+':'+str(d['signatures'][2]['personal']['valid'])" < "$T/v.json")" "revoked:False"
call POST /user-keys/$REGKEY/revoke "$ADM" '{"reason":"again"}'; expect "revoking twice is refused" "$CODE" 409
call GET /audit "$ADM"
expect "key events are audited" "$(echo "$BODY" | j "all(any(l['action']==a for l in d['logs']) for a in ('USER_KEY_REGISTERED','USER_KEY_RETIRED','USER_KEY_REVOKED','APPROVAL_COUNTERSIGNED'))")" True

echo "== policy on: every approval needs a personal signature"
export REQUIRE_PERSONAL_SIGNATURES=true REQUIRE_ADMIN_ENROLLMENT=true
dc up -d --force-recreate --wait backend >/dev/null 2>&1 && ok "backend restarted with the policy on" || { bad "backend did not restart"; exit 1; }
register reg2 "$REG"; expect "having lost every key, the registrar cannot enrol a new one alone" "$CODE" 409
call GET /auth/me "$REG"; REGID=$(echo "$BODY" | j "d['id']")
call POST /users/$REGID/keys/enroll "$ADM"; expect "an administrator allows it" "$CODE" 200
register reg2 "$REG"; expect "the registrar registers a replacement key" "$CODE" 201
call POST /users "$ADM" '{"email":"fresh@university.edu","role":"faculty","password":"fresh-user-password-1"}'; FRESHID=$(echo "$BODY" | j "d['id']")
call POST /auth/login "" '{"email":"fresh@university.edu","password":"fresh-user-password-1"}'; FRESH=$(echo "$BODY" | j "d['token']")
register fresh "$FRESH"; expect "with REQUIRE_ADMIN_ENROLLMENT even a first key needs an administrator" "$CODE" 409
call POST /users/$FRESHID/keys/enroll "$ADM"
register fresh "$FRESH"; expect "and then it can be enrolled" "$CODE" 201
new_cred; PID=$NEWID; PH=$NEWHASH
call POST /credentials/$PID/approve "$EXC" ""; expect "approving without a signature is refused" "$CODE" 409
approve_with $PID "$EXC" exc2 exam_cell; expect "so is approving before the faculty signature is added" "$CODE" 409
chal=$(challenge_of "$PID" faculty "$PH"); call POST /credentials/$PID/countersign "$FAC" "{\"webauthn\":$(assertion fac "$chal")}"; expect "faculty adds theirs" "$CODE" 200
approve_with $PID "$EXC" exc2 exam_cell; expect "now the exam cell can approve with theirs" "$CODE" 200
call POST /credentials/$PID/approve "$REG" ""; expect "the registrar still needs one" "$CODE" 409
approve_with $PID "$REG" reg2 registrar; expect "registrar approves with a signature" "$CODE" 200
approve_with $PID "$ADM" adm university; expect "admin approves with a signature" "$CODE" 200
curl -s "$BASE/verify/$PID" > "$T/v.json"
expect "the credential is VALID" "$(j "d['verdict']" < "$T/v.json")" VALID
expect "all four approvals carry a verified personal signature" "$(j "sum(1 for s in d['signatures'] if s['personal'] and s['personal']['valid'])" < "$T/v.json")" 4
expect "an independent check agrees" "$($SIM check "$T/v.json" 2>&1)" "independently verified 4 personal signature(s)"
curl -s "$BASE/verify/$ID1" > "$T/v.json"; expect "credentials from before the policy are not retroactively invalid" "$(j "d['verdict']" < "$T/v.json")" PENDING
OUT=$(dc run --rm -T -e WEBAUTHN_RP_ID=evil.example backend 2>&1); [[ "$OUT" == *"WEBAUTHN_RP_ID must be"* ]] && ok "an unrelated WEBAUTHN_RP_ID is refused at startup" || bad "bad rp id accepted: $OUT"

echo
[ $fails -eq 0 ] && echo "ALL PERSONAL-SIGNATURE CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
