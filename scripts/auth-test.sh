#!/usr/bin/env bash
# Sessions, password reset links, password rules and two-factor sign-in end to end.
# Usage: scripts/auth-test.sh
#
# Runs a throwaway copy of the development stack ("acvsauth"). It publishes the same ports as the main
# dev stack, so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

T=$(mktemp -d)
dc() { docker compose -p acvsauth "$@"; }
trap 'dc down -v >/dev/null 2>&1; rm -rf "$T"' EXIT

PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2)
BASE=http://localhost:3000/api/v1
fails=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
UA="acvs-auth-test"
call() { # METHOD PATH TOKEN [BODY] -> CODE, BODY
  local args=(-s -o "$T/body" -w '%{http_code}' -X "$1" "$BASE$2" -H 'Content-Type: application/json' -A "$UA")
  [ -n "${3:-}" ] && args+=(-H "Authorization: Bearer $3")
  [ "$1" = POST ] && args+=(-H "X-Nonce: $(python3 -c 'import uuid; print(uuid.uuid4())')" -H "X-Timestamp: $(date +%s)")
  [ -n "${4:-}" ] && args+=(-d "$4")
  CODE=$(curl "${args[@]}"); BODY=$(cat "$T/body")
}
login_as() { # EMAIL PASSWORD -> prints token
  call POST /auth/login "" "{\"email\":\"$1\",\"password\":\"$2\"}"; echo "$BODY" | j "d.get('token','')"
}
DBX() { dc exec -T postgres psql -U acvs -d acvs -qAt -c "$1" 2>&1; }
uid() { DBX "SELECT id FROM users WHERE email='$1@university.edu'"; }
logs() { dc logs backend 2>&1; }

echo "== start"
export SEED_DEMO_PASSWORD=$PASS LOGIN_ACCOUNT_FAILURES=1000 LOGIN_IP_PER_MIN=1000 REQUIRE_MFA_ROLES=registrar
dc up -d --build --wait >/dev/null 2>&1 && ok "stack healthy" || { bad "stack did not start"; exit 1; }
FAC=$(login_as faculty@university.edu "$PASS"); ADM=$(login_as admin@university.edu "$PASS"); EXC=$(login_as examcell@university.edu "$PASS")
[ -n "$FAC" ] && [ -n "$ADM" ] && [ -n "$EXC" ] || { bad "could not sign in"; exit 1; }

echo "== listing sessions"
FAC2=$(login_as faculty@university.edu "$PASS")
call GET /auth/sessions "$FAC"; expect "two live sessions" "$(echo "$BODY" | j "len(d['sessions'])")" 2
expect "exactly one is marked as the current one" "$(echo "$BODY" | j "sum(1 for s in d['sessions'] if s['current'])")" 1
expect "and it is the one that asked" "$(echo "$BODY" | j "[s['user_agent'] for s in d['sessions'] if s['current']][0]")" "$UA"
echo "$BODY" | j "all(s['ip'] for s in d['sessions'])" | grep -q True && ok "each shows where it came from" || bad "no ip recorded: $BODY"
call GET /auth/sessions "" ; expect "listing needs a sign-in" "$CODE" 401
call GET /auth/sessions "$ADM"; expect "others only see their own" "$(echo "$BODY" | j "len(d['sessions'])")" 1

echo "== revoking sessions"
SID2=$(call GET /auth/sessions "$FAC2" >/dev/null; echo "$BODY" | j "[s['id'] for s in d['sessions'] if s['current']][0]")
SID1=$(call GET /auth/sessions "$FAC" >/dev/null; echo "$BODY" | j "[s['id'] for s in d['sessions'] if s['current']][0]")
call POST "/auth/sessions/$SID1/revoke" "$FAC" '{}'; expect "cannot revoke the session in use (use logout)" "$CODE" 400
call POST "/auth/sessions/$SID2/revoke" "$EXC" '{}'; expect "cannot revoke someone else's session" "$CODE" 404
call GET /auth/me "$FAC2"; expect "...which therefore still works" "$CODE" 200
call POST "/auth/sessions/$SID2/revoke" "$FAC" '{}'; expect "revoke the other session" "$CODE" 200
call GET /auth/me "$FAC2"; expect "its token stops working at once" "$CODE" 401
call POST "/auth/sessions/$SID2/revoke" "$FAC" '{}'; expect "revoking it again is a 404" "$CODE" 404
call GET /auth/sessions "$FAC"; expect "and it left the list" "$(echo "$BODY" | j "len(d['sessions'])")" 1
FAC2=$(login_as faculty@university.edu "$PASS"); FAC3=$(login_as faculty@university.edu "$PASS")
call POST /auth/sessions/revoke-others "$FAC" '{}'; expect "sign out everywhere else" "$(echo "$BODY" | j "d['revoked']")" 2
call GET /auth/me "$FAC"; expect "this session survives" "$CODE" 200
call GET /auth/me "$FAC3"; expect "the others do not" "$CODE" 401

echo "== administrator signs a user out"
FAC2=$(login_as faculty@university.edu "$PASS"); FID=$(uid faculty)
call POST "/users/$FID/sessions/revoke" "$FAC" '{}'; expect "a non-admin cannot" "$CODE" 403
call POST "/users/$(uid admin)/sessions/revoke" "$ADM" '{}'; expect "an admin uses 'sign out others' for themselves" "$CODE" 400
call POST "/users/00000000-0000-0000-0000-000000000000/sessions/revoke" "$ADM" '{}'; expect "unknown user" "$CODE" 404
call POST "/users/$FID/sessions/revoke" "$ADM" '{}'; expect "revokes every session of that user" "$(echo "$BODY" | j "d['revoked']")" 2
call GET /auth/me "$FAC"; expect "first token is dead" "$CODE" 401
call GET /auth/me "$FAC2"; expect "second token is dead" "$CODE" 401
call GET /auth/me "$ADM"; expect "the admin is unaffected" "$CODE" 200

echo "== old sessions are deleted"
U=$(uid auditor)
DBX "INSERT INTO sessions (id,user_id,expires_at,created_at) VALUES
  (gen_random_uuid(),'$U', now()-interval '9 days', now()-interval '10 days'),
  (gen_random_uuid(),'$U', now()+interval '1 day', now()-interval '10 days'),
  (gen_random_uuid(),'$U', now()-interval '1 day', now()-interval '2 days'),
  (gen_random_uuid(),'$U', now()+interval '1 day', now()-interval '3 days')" >/dev/null
DBX "UPDATE sessions SET revoked_at = now()-interval '8 days' WHERE user_id='$U' AND expires_at > now() AND created_at < now()-interval '9 days'" >/dev/null
expect "four rows planted (expired long ago, revoked long ago, expired yesterday, live)" "$(DBX "SELECT count(*) FROM sessions WHERE user_id='$U'")" 4
dc restart backend >/dev/null 2>&1; dc up -d --wait >/dev/null 2>&1; sleep 2
expect "the cleanup removes the two that finished over a week ago" "$(DBX "SELECT count(*) FROM sessions WHERE user_id='$U'")" 2
expect "and keeps the recent and the live ones" "$(DBX "SELECT count(*) FROM sessions WHERE user_id='$U' AND expires_at > now()")" 1

echo "== password rules"
ADM=$(login_as admin@university.edu "$PASS")
call POST /users "$ADM" '{"email":"new.person@university.edu","role":"faculty","password":"Password1234"}'; expect "a common password is refused" "$CODE" 400
call POST /users "$ADM" '{"email":"new.person@university.edu","role":"faculty","password":"aaaaaaaaaaaaaa"}'; expect "a repeated character is refused" "$CODE" 400
call POST /users "$ADM" '{"email":"new.person@university.edu","role":"faculty","password":"xx-new.person-xx"}'; expect "one built from the e-mail address is refused" "$CODE" 400
call POST /users "$ADM" '{"email":"new.person@university.edu","role":"faculty","password":"a fine passphrase 77"}'; expect "a reasonable one is accepted" "$CODE" 201
call POST "/users/$(uid faculty)/password" "$ADM" '{"password":"qwertyuiop12"}'; expect "an admin cannot reset to a common password either" "$CODE" 400
call POST /auth/password "$ADM" "{\"current_password\":\"$PASS\",\"new_password\":\"admin@university.edu\"}"; expect "nor can people change to one" "$CODE" 400

echo "== password reset links"
FID=$(uid faculty); FAC=$(login_as faculty@university.edu "$PASS")
call POST "/users/$FID/reset-link" "$FAC" '{}'; expect "only an admin can issue one" "$CODE" 403
call POST "/users/$(uid admin)/reset-link" "$ADM" '{}'; expect "not for yourself" "$CODE" 400
call POST "/users/00000000-0000-0000-0000-000000000000/reset-link" "$ADM" '{}'; expect "unknown user" "$CODE" 404
call POST "/users/$FID/reset-link" "$ADM" '{}'; expect "an admin issues a link" "$CODE" 200
TOK=$(echo "$BODY" | j "d['token']"); expect "the link carries the token" "$(echo "$BODY" | j "d['path']")" "/#/reset/$TOK"
[ "$(DBX "SELECT count(*) FROM password_resets WHERE encode(token_hash,'escape') LIKE '%$TOK%'")" = 0 ] && ok "only a hash of the token is stored" || bad "token stored in clear"
call POST /auth/reset-password "" "{\"token\":\"nonsense\",\"new_password\":\"a brand new passphrase 1\"}"; expect "a made-up token is refused" "$CODE" 400
call POST /auth/reset-password "" "{\"token\":\"$TOK\",\"new_password\":\"Password1234\"}"; expect "a weak new password is refused" "$CODE" 400
call POST /auth/reset-password "" "{\"token\":\"$TOK\",\"new_password\":\"short\"}"; expect "a short one too" "$CODE" 400
call POST /auth/reset-password "" "{\"token\":\"$TOK\",\"new_password\":\"a brand new passphrase 1\"}"; expect "the link still works after those refusals" "$CODE" 200
call GET /auth/me "$FAC"; expect "the person is signed out everywhere" "$CODE" 401
expect "the old password no longer works" "$(login_as faculty@university.edu "$PASS")" ""
[ -n "$(login_as faculty@university.edu 'a brand new passphrase 1')" ] && ok "the new one does" || bad "new password rejected"
call POST /auth/reset-password "" "{\"token\":\"$TOK\",\"new_password\":\"another passphrase 2 ok\"}"; expect "a link works only once" "$CODE" 400
call POST "/users/$FID/reset-link" "$ADM" '{}'; T1=$(echo "$BODY" | j "d['token']")
call POST "/users/$FID/reset-link" "$ADM" '{}'; T2=$(echo "$BODY" | j "d['token']")
call POST /auth/reset-password "" "{\"token\":\"$T1\",\"new_password\":\"another passphrase 2 ok\"}"; expect "issuing a new link cancels the earlier one" "$CODE" 400
DBX "UPDATE password_resets SET expires_at = now() - interval '1 minute' WHERE used_at IS NULL" >/dev/null
call POST /auth/reset-password "" "{\"token\":\"$T2\",\"new_password\":\"another passphrase 2 ok\"}"; expect "an expired link is refused" "$CODE" 400
call POST "/users/$FID/active" "$ADM" '{"active":false}'
call POST "/users/$FID/reset-link" "$ADM" '{}'; expect "no link for a deactivated account" "$CODE" 400
call POST "/users/$FID/active" "$ADM" '{"active":true}'
call GET "/audit?limit=200" "$ADM"
for a in PASSWORD_RESET_ISSUED PASSWORD_RESET_USED SESSION_REVOKED SESSIONS_REVOKED USER_SESSIONS_REVOKED; do
  echo "$BODY" | j "any(l['action']=='$a' for l in d['logs'])" | grep -q True && ok "audit log has $a" || bad "audit log lacks $a"
done
echo "$BODY" | grep -q "$TOK" && bad "a token appears in the audit log" || ok "and no token or password appears in it"

echo "== two-factor sign-in: turning it on"
FP='a brand new passphrase 1'
code() { python3 scripts/totp.py "$1" "${2:-0}"; }
calm() { DBX "DELETE FROM rate_limits WHERE key LIKE 'mfa:%'" >/dev/null; }   # the wrong-code budget is deliberately small
fresh_steps() { DBX "UPDATE user_totp SET last_step = 0" >/dev/null; }   # lets a test reuse a code without waiting 30 s
FAC=$(login_as faculty@university.edu "$FP"); FAC_B=$(login_as faculty@university.edu "$FP")
call GET /auth/totp "$FAC"; expect "off by default" "$(echo "$BODY" | j "d['enabled']")" False
expect "and not required for faculty" "$(echo "$BODY" | j "d['required']")" False
call POST /auth/totp/setup "$FAC" '{"password":"wrong"}'; expect "setup needs the password" "$CODE" 400
call POST /auth/totp/setup "$FAC" "{\"password\":\"$FP\"}"; expect "setup gives a secret" "$CODE" 200
SECRET=$(echo "$BODY" | j "d['secret']"); URI=$(echo "$BODY" | j "d['uri']")
[[ "$URI" == otpauth://totp/ACVS:faculty%40university.edu\?secret=$SECRET\&issuer=ACVS* ]] && ok "and an otpauth:// link for QR codes" || bad "uri: $URI"
expect "the secret is 32 base32 characters" "$(echo -n "$SECRET" | grep -cE '^[A-Z2-7]{32}$')" 1
[ "$(DBX "SELECT count(*) FROM user_totp WHERE encode(secret_enc,'escape') LIKE '%$SECRET%'")" = 0 ] && ok "stored sealed, not in clear" || bad "secret stored in clear"
call GET /auth/totp "$FAC"; expect "not on until a code is proven" "$(echo "$BODY" | j "d['enabled']")" False
FAC_LOGIN=$(login_as faculty@university.edu "$FP"); [ -n "$FAC_LOGIN" ] && ok "sign-in still needs only the password meanwhile" || bad "sign-in blocked before confirmation"
call POST /auth/totp/enable "$FAC" '{"code":"000000"}'; expect "a wrong code does not turn it on" "$CODE" 400
call POST /auth/totp/enable "$FAC" '{"code":"abcdef"}'; expect "nor does garbage" "$CODE" 400
call POST /auth/totp/enable "$FAC" "{\"code\":\"$(code "$SECRET")\"}"; expect "the right code turns it on" "$CODE" 200
RECOVERY=$(echo "$BODY" | j "' '.join(d['recovery_codes'])"); expect "and shows ten recovery codes" "$(echo "$RECOVERY" | wc -w | tr -d ' ')" 10
call GET /auth/me "$FAC_B"; expect "sessions opened with a password alone are ended" "$CODE" 401
call GET /auth/me "$FAC"; expect "the one that set it up continues" "$CODE" 200
call GET /auth/totp "$FAC"; expect "status: on" "$(echo "$BODY" | j "d['enabled']")" True
expect "with ten recovery codes left" "$(echo "$BODY" | j "d['recovery_codes_left']")" 10
call POST /auth/totp/setup "$FAC" "{\"password\":\"$FP\"}"; expect "cannot start a second setup over a working one" "$CODE" 409
[ "$(DBX "SELECT count(*) FROM totp_recovery WHERE code_hash IS NOT NULL")" = 10 ] && ok "recovery codes are stored as hashes" || bad "recovery rows"
call GET /users "$ADM"; expect "the user list shows who has it" "$(echo "$BODY" | j "[u['two_factor'] for u in d['users'] if u['email']=='faculty@university.edu'][0]")" True

echo "== two-factor sign-in: signing in"
call POST /auth/login "" "{\"email\":\"faculty@university.edu\",\"password\":\"$FP\"}"
expect "the password alone no longer gives a session" "$(echo "$BODY" | j "d.get('token')")" None
expect "it asks for the code" "$(echo "$BODY" | j "d['mfa_required']")" True
MT=$(echo "$BODY" | j "d['mfa_token']")
call GET /auth/me "$MT"; expect "the interim token is no use as a session" "$CODE" 401
call POST /auth/login/mfa "" "{\"mfa_token\":\"garbage\",\"code\":\"$(code "$SECRET" 1)\"}"; expect "a made-up interim token is refused" "$CODE" 401
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"000000\"}"; expect "a wrong code is refused" "$CODE" 401
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$(code "$SECRET" 1)\"}"; expect "the right code signs in" "$CODE" 200
T1=$(echo "$BODY" | j "d['token']"); call GET /auth/me "$T1"; expect "and the session works" "$CODE" 200
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$(code "$SECRET" 1)\"}"; expect "the same code cannot be used twice" "$CODE" 401
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$(code "$SECRET" 0)\"}"; expect "nor can an earlier one once a later one was used" "$CODE" 401
fresh_steps
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$(code "$SECRET" 5)\"}"; expect "a code from minutes away is refused" "$CODE" 401
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$(code "$SECRET" -1)\"}"; expect "one step of clock drift is tolerated" "$CODE" 200
fresh_steps
# a password change must not be a way round it
call POST /auth/login "" "{\"email\":\"faculty@university.edu\",\"password\":\"wrong password here\"}"; expect "wrong password still just 401" "$CODE" 401
echo "-- recovery codes"
calm
R1=$(echo "$RECOVERY" | cut -d' ' -f1)
call POST /auth/login "" "{\"email\":\"faculty@university.edu\",\"password\":\"$FP\"}"; MT=$(echo "$BODY" | j "d['mfa_token']")
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$R1\"}"; expect "a recovery code signs in" "$CODE" 200
T2=$(echo "$BODY" | j "d['token']")
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$R1\"}"; expect "but only once" "$CODE" 401
call GET /auth/totp "$T2"; expect "nine are left" "$(echo "$BODY" | j "d['recovery_codes_left']")" 9
R2=$(echo "$RECOVERY" | cut -d' ' -f2); call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$(echo "$R2" | tr 'A-Z' 'a-z' | tr -d '-')\"}"; expect "case and dashes do not matter" "$CODE" 200
echo "-- regenerating recovery codes"
calm
call POST /auth/totp/recovery-codes "$T2" "{\"password\":\"$FP\",\"code\":\"wrong\"}"; expect "needs a valid code" "$CODE" 400
call POST /auth/totp/recovery-codes "$T2" "{\"password\":\"wrong\",\"code\":\"$(code "$SECRET" 1)\"}"; expect "and the password" "$CODE" 400
call POST /auth/totp/recovery-codes "$T2" "{\"password\":\"$FP\",\"code\":\"$(code "$SECRET" 1)\"}"; expect "new codes are issued" "$(echo "$BODY" | j "len(d['recovery_codes'])")" 10
NEWR=$(echo "$BODY" | j "d['recovery_codes'][0]")
call POST /auth/login "" "{\"email\":\"faculty@university.edu\",\"password\":\"$FP\"}"; MT=$(echo "$BODY" | j "d['mfa_token']")
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$(echo "$RECOVERY" | cut -d' ' -f3)\"}"; expect "an old recovery code no longer works" "$CODE" 401
call POST /auth/login/mfa "" "{\"mfa_token\":\"$MT\",\"code\":\"$NEWR\"}"; expect "a new one does" "$CODE" 200

echo "== two-factor sign-in: guessing"
AUD_PASS=$PASS
AUD=$(login_as auditor@university.edu "$AUD_PASS")
call POST /auth/totp/setup "$AUD" "{\"password\":\"$AUD_PASS\"}"; ASEC=$(echo "$BODY" | j "d['secret']")
call POST /auth/totp/enable "$AUD" "{\"code\":\"$(code "$ASEC")\"}"
call POST /auth/login "" "{\"email\":\"auditor@university.edu\",\"password\":\"$AUD_PASS\"}"; AMT=$(echo "$BODY" | j "d['mfa_token']")
for i in 1 2 3 4 5; do call POST /auth/login/mfa "" "{\"mfa_token\":\"$AMT\",\"code\":\"00000$i\"}"; [ "$CODE" = 401 ] || bad "guess $i: $CODE"; done
call POST /auth/login/mfa "" "{\"mfa_token\":\"$AMT\",\"code\":\"$(code "$ASEC" 1)\"}"; expect "after five wrong codes even the right one is refused (429)" "$CODE" 429
[ -n "$(echo "$BODY" | j "d.get('retry_after','')")" ] && ok "and says when to retry" || bad "no retry_after"
call GET /audit?limit=200 "$ADM"
echo "$BODY" | j "sum(1 for l in d['logs'] if l['action']=='LOGIN_MFA_FAILED')>=5" | grep -q True && ok "failed codes are audit-logged" || bad "no LOGIN_MFA_FAILED entries"
DBX "DELETE FROM rate_limits WHERE key LIKE 'mfa:%'" >/dev/null

echo "== two-factor sign-in: turning it off"
calm; fresh_steps
call POST /auth/totp/disable "$T2" "{\"password\":\"wrong\",\"code\":\"$(code "$SECRET" 1)\"}"; expect "needs the password" "$CODE" 400
call POST /auth/totp/disable "$T2" "{\"password\":\"$FP\",\"code\":\"000000\"}"; expect "and a valid code" "$CODE" 400
call POST /auth/totp/disable "$T2" "{\"password\":\"$FP\",\"code\":\"$(code "$SECRET" 1)\"}"; expect "then it turns off" "$CODE" 200
call GET /auth/totp "$T2"; expect "status: off" "$(echo "$BODY" | j "d['enabled']")" False
expect "recovery codes are gone" "$(DBX "SELECT count(*) FROM totp_recovery WHERE user_id='$(uid faculty)'")" 0
[ -n "$(login_as faculty@university.edu "$FP")" ] && ok "and the password alone signs in again" || bad "cannot sign in"

echo "== two-factor sign-in: required for a role (registrar)"
call POST /auth/login "" "{\"email\":\"registrar@university.edu\",\"password\":\"$PASS\"}"
REG=$(echo "$BODY" | j "d['token']"); expect "without it set up, sign-in still gives a restricted session" "$(echo "$BODY" | j "d['mfa_setup_required']")" True
call GET /auth/me "$REG"; expect "/auth/me tells the page to send them to setup" "$(echo "$BODY" | j "d['mfa_setup_required']")" True
call GET /credentials "$REG"; expect "everything else is refused (403)" "$CODE" 403
echo "$BODY" | grep -q "set up first" && ok "with a clear message" || bad "message: $BODY"
call POST "/credentials/00000000-0000-0000-0000-000000000000/approve" "$REG" '{}'; expect "approving is refused too" "$CODE" 403
call GET /auth/totp "$REG"; expect "the status page works" "$(echo "$BODY" | j "d['setup_required']")" True
expect "and says it is required" "$(echo "$BODY" | j "d['required']")" True
call POST /auth/totp/setup "$REG" "{\"password\":\"$PASS\"}"; RSEC=$(echo "$BODY" | j "d['secret']")
call POST /auth/totp/enable "$REG" "{\"code\":\"$(code "$RSEC")\"}"; expect "setting it up works from the restricted session" "$CODE" 200
call GET /credentials "$REG"; expect "and then the same session is fully usable" "$CODE" 200
call POST /auth/totp/disable "$REG" "{\"password\":\"$PASS\",\"code\":\"$(code "$RSEC" 1)\"}"; expect "a required role cannot turn it off" "$CODE" 403
call POST /auth/login "" "{\"email\":\"registrar@university.edu\",\"password\":\"$PASS\"}"; expect "later sign-ins need the code" "$(echo "$BODY" | j "d['mfa_required']")" True
echo "-- an administrator resets a lost device"
RID=$(uid registrar)
call POST "/users/$RID/totp/reset" "$T2" '{}'; expect "a non-admin cannot" "$CODE" 403
call POST "/users/$(uid admin)/totp/reset" "$ADM" '{}'; expect "an admin cannot reset their own" "$CODE" 400
call POST "/users/00000000-0000-0000-0000-000000000000/totp/reset" "$ADM" '{}'; expect "unknown user" "$CODE" 404
call POST "/users/$RID/totp/reset" "$ADM" '{}'; expect "resetting removes it" "$(echo "$BODY" | j "d['had_two_factor']")" True
call GET /auth/me "$REG"; expect "and ends their sessions" "$CODE" 401
call POST /auth/login "" "{\"email\":\"registrar@university.edu\",\"password\":\"$PASS\"}"; expect "the role must set it up again" "$(echo "$BODY" | j "d['mfa_setup_required']")" True
REG=$(echo "$BODY" | j "d['token']")
call POST /auth/totp/setup "$REG" "{\"password\":\"$PASS\"}"; RSEC=$(echo "$BODY" | j "d['secret']")
call POST /auth/totp/enable "$REG" "{\"code\":\"$(code "$RSEC")\"}" 
echo "-- the operator command (no administrator can sign in)"
OUT=$(dc exec -T backend ./server totp-reset registrar@university.edu 2>&1); echo "$OUT" | grep -q 'two-factor sign-in removed for registrar@university.edu' && ok "server totp-reset removes it" || bad "totp-reset: $OUT"
expect "really removed" "$(DBX "SELECT count(*) FROM user_totp WHERE user_id='$RID'")" 0
call GET /auth/me "$REG"; expect "and ends their sessions" "$CODE" 401
OUT=$(dc exec -T backend ./server totp-reset nobody@example.com 2>&1); echo "$OUT" | grep -q 'no user' && ok "an unknown address is reported" || bad "unknown: $OUT"
call GET "/audit?limit=300" "$ADM"
for a in TOTP_ENABLED TOTP_DISABLED TOTP_RECOVERY_CODE_USED TOTP_RECOVERY_CODES_REPLACED TOTP_RESET_BY_ADMIN TOTP_RESET_BY_OPERATOR; do
  echo "$BODY" | j "any(l['action']=='$a' for l in d['logs'])" | grep -q True && ok "audit log has $a" || bad "audit log lacks $a"
done
echo "$BODY" | grep -q "$SECRET" && bad "a two-factor secret appears in the audit log" || ok "and no secret or code appears in it"

echo "== bad configuration is refused at startup"
OUT=$(dc run --rm -T -e REQUIRE_MFA_ROLES=registrar,wizard backend ./server 2>&1); echo "$OUT" | grep -q "'wizard' is not a role" && ok "an unknown role in REQUIRE_MFA_ROLES" || bad "accepted: $OUT"

echo
[ $fails -eq 0 ] && echo "ALL AUTH CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
