#!/usr/bin/env bash
# Proves that request limits are shared by every backend instance, survive restarts, throttle guessing at one
# account from many addresses, treat people behind one address fairly, and keep working when the database does not.
# Usage: scripts/ratelimit-test.sh
#
# Runs a throwaway copy of the development stack ("acvsrl") with TWO backend instances on one database.
# It publishes the same ports as the main dev stack, so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

T=$(mktemp -d)
dc() { docker compose -p acvsrl "$@"; }
trap 'dc down -v >/dev/null 2>&1; rm -rf "$T"' EXIT

PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2)
ROOT=http://localhost:8000
fails=0
BUF=(); BUFFERING=0
say() { if [ $BUFFERING = 1 ]; then BUF+=("$1"); else echo "$1"; fi; }
ok() { say "  ok   $1"; }
bad() { say "  FAIL $1"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
DBX() { dc exec -T postgres psql -U acvs -d acvs -qAt -c "$1" 2>&1; }
# via N ARGS...: run a command inside backend instance N (they share one database)
via() { local n=$1; shift; dc exec -T --index "$n" backend "$@"; }
# req N METHOD PATH IP [TOKEN] [BODY] -> sets CODE, BODY, RETRY (calls instance N as client address IP; PATH is absolute)
req() {
  local n=$1 m=$2 path=$3 ip=$4 token=${5:-} body=${6:-}
  local args=(curl -s -i -X "$m" "$ROOT$path" -H "X-Forwarded-For: $ip" -H 'Content-Type: application/json')
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  [ -n "$body" ] && args+=(-d "$body")
  local out; out=$(via "$n" "${args[@]}")
  CODE=$(echo "$out" | head -1 | awk '{print $2}')
  RETRY=$(echo "$out" | tr -d '\r' | grep -i '^retry-after:' | awk '{print $2}')
  BODY=$(echo "$out" | tr -d '\r' | sed -n '/^$/,$p' | tail -n +2)
}
login() { # N IP EMAIL PASSWORD
  req "$1" POST /api/v1/auth/login "$2" "" "{\"email\":\"$3\",\"password\":\"$4\"}"
}
# Wait until the database clock is within the first MAX seconds of a SECS-long window, so a test that must
# stay inside one window is not split by a boundary.
early_in_window() {
  for _ in $(seq 1 130); do
    [ "$(DBX "SELECT (floor(extract(epoch FROM now()))::bigint % $1) < $2")" = t ] && return 0; sleep 1
  done
}
# Limits are fixed windows, so a section that counts hits must run inside ONE window. A slow machine can drag it
# across a boundary; then its counts mean nothing, so run it again (from the start of the next window) with
# fresh client addresses. FN gets the attempt number; its results are shown only for the attempt that fit.
win() { DBX "SELECT floor(extract(epoch FROM now()))::bigint / 60"; }
in_one_window() { # FN
  local a w0 w1 line
  for a in 1 2 3 4; do
    early_in_window 60 3; w0=$(win); BUF=(); BUFFERING=1
    "$1" "$a"
    BUFFERING=0; w1=$(win)
    if [ "$w0" = "$w1" ] || [ "$a" = 4 ]; then
      for line in "${BUF[@]}"; do echo "$line"; case "$line" in "  FAIL"*) fails=$((fails + 1)) ;; esac; done
      return 0
    fi
    echo "  (the one-minute window ended while '$1' was running; running it again)"
  done
}
codes() { # N IP COUNT PATH [TOKEN]: fire COUNT requests inside the container, print "<count> <code>" lines
  via "$1" sh -c "for i in \$(seq 1 $3); do curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: $2' ${5:+-H 'Authorization: Bearer $5'} $ROOT$4; done | sort | uniq -c | awk '{print \$2\":\"\$1}' | tr '\n' ' '"
}
count_of() { echo "$1" | tr ' ' '\n' | grep "^$2:" | cut -d: -f2; }

echo "== start (two backend instances, one database)"
export SEED_DEMO_PASSWORD=$PASS LOGIN_ACCOUNT_FAILURES=5 LOGIN_ACCOUNT_WINDOW_SECS=60
dc up -d --build --wait --scale backend=2 >/dev/null 2>&1 && ok "stack healthy" || { bad "stack did not start"; exit 1; }
[ "$(dc ps -q backend | wc -l | tr -d ' ')" = 2 ] && ok "two backend instances are running" || bad "expected two instances"

s_shared() {
  local a=$1 ip=100.77.$1.1 all401=1 i
  for i in $(seq 1 10); do login $((i % 2 + 1)) $ip "nobody$i@example.com" "wrong-password-$i"; [ "$CODE" = 401 ] || all401=0; done
  [ $all401 = 1 ] && ok "ten login attempts, alternating between the two instances, are all allowed" || bad "an early attempt was refused"
  login 1 $ip "nobody11@example.com" "wrong-password"; expect "the 11th is refused by instance 1" "$CODE" 429
  local retry=$RETRY body=$BODY
  login 2 $ip "nobody12@example.com" "wrong-password"; expect "and instance 2 refuses it too (a per-process limiter would have allowed 10 more)" "$CODE" 429
  case "$retry" in ''|*[!0-9]*) bad "no numeric Retry-After header (got '$retry')" ;; *) [ "$retry" -ge 1 ] && [ "$retry" -le 60 ] && ok "the refusal carries Retry-After: $retry" || bad "Retry-After out of range: $retry" ;; esac
  expect "the body says when to retry" "$(echo "$body" | j "d['retry_after']==$retry")" True
  login 1 100.77.$a.2 "nobody@example.com" "wrong-password"; expect "another client address is unaffected" "$CODE" 401
}
echo "== the limit is shared by every instance"
in_one_window s_shared

s_restart() {
  local ip=100.76.$1.1 i
  for i in $(seq 1 11); do login $((i % 2 + 1)) $ip "nobody$i@example.com" "wrong-password"; done
  expect "(setup) the address is over its limit" "$CODE" 429
  dc restart backend >/dev/null 2>&1; dc up -d --wait --scale backend=2 >/dev/null 2>&1
  login 1 $ip "nobody13@example.com" "wrong-password"; expect "still refused after both instances restarted" "$CODE" 429
  expect "the counter is a row in the database" "$(DBX "SELECT hits >= 11 FROM rate_limits WHERE key = 'login:$ip'")" t
}
echo "== the limit survives a restart"
in_one_window s_restart

s_account() {
  local i
  for i in 1 2 3 4 5; do login $((i % 2 + 1)) 100.78.$1.$i "faculty@university.edu" "wrong-password-$i"; [ "$CODE" = 401 ] || bad "failure $i was $CODE"; done
  ok "five failures from five different addresses are each answered 401"
  login 1 100.78.$1.50 "faculty@university.edu" "$PASS"; expect "the account is now throttled, even for the right password, from a new address" "$CODE" 429
  login 2 100.78.$1.51 "examcell@university.edu" "$PASS"; expect "other accounts are not affected" "$CODE" 200
  for i in 1 2 3 4 5; do login 1 100.78.$1.1$i "ghost@example.com" "wrong-password"; done
  login 1 100.78.$1.99 "ghost@example.com" "wrong-password"; expect "an account that does not exist is throttled identically (no way to tell registered emails apart)" "$CODE" 429
}
echo "== guessing one account from many addresses is throttled (limit: 5 failures per minute here)"
in_one_window s_account
login 1 100.78.9.1 "admin@university.edu" "$PASS"; ADM_TOKEN=$(echo "$BODY" | j "d['token']")
req 1 GET "/api/v1/audit?limit=100" 100.78.9.1 "$ADM_TOKEN"
expect "throttled attempts are audit-logged" "$(echo "$BODY" | j "any(l['action']=='LOGIN_THROTTLED' for l in d['logs'])")" True
expect "the audit entry does not contain the password" "$(echo "$BODY" | grep -c "$PASS")" 0
echo "  (waiting for the throttle window to end)"
for _ in $(seq 1 130); do
  login 1 100.78.8.$((RANDOM % 200 + 1)) "faculty@university.edu" "$PASS"; [ "$CODE" = 200 ] && break; sleep 2
done
expect "when the window ends the account works again" "$CODE" 200
FAC=$(echo "$BODY" | j "d['token']")
login 2 100.79.9.1 "registrar@university.edu" "$PASS"; REG=$(echo "$BODY" | j "d['token']")

s_nat() {
  local ip=100.79.$1.1 ip2=100.79.$1.2 OUT
  OUT=$(codes 1 $ip 300 /api/v1/auth/me "$FAC"); expect "a signed-in user can make 300 requests from one address (limit 600 per user)" "$(count_of "$OUT" 200)" 300
  OUT=$(codes 2 $ip 260 /health); [ "$(count_of "$OUT" 200)" = 240 ] && [ "$(count_of "$OUT" 429)" = 20 ] && ok "anonymous requests from that address are cut off at 240 (got: $OUT)" || bad "anonymous limit: $OUT"
  req 1 GET /api/v1/auth/me $ip "$REG"; expect "another signed-in user at the same address is still served" "$CODE" 200
  OUT=$(codes 1 $ip2 300 /api/v1/auth/me "not-a-real-token"); [ "$(count_of "$OUT" 401)" = 240 ] && [ "$(count_of "$OUT" 429)" = 60 ] && ok "an invented token earns no bucket of its own (got: $OUT)" || bad "forged token: $OUT"
}
echo "== people behind one address do not share one budget"
in_one_window s_nat

echo "== the limiter keeps working when the database does not"
dc stop postgres >/dev/null 2>&1
S=$(date +%s); req 1 GET /health 100.80.0.1; E=$(date +%s)
[ "$CODE" = 200 ] && [ $((E - S)) -le 3 ] && ok "requests are still answered promptly with the database down" || bad "health with db down: $CODE after $((E - S))s"
S=$(date +%s); login 1 100.80.0.2 "faculty@university.edu" "$PASS"; E=$(date +%s)
[ $((E - S)) -le 8 ] && ok "a login fails fast instead of hanging (HTTP $CODE)" || bad "login hung for $((E - S))s"
dc start postgres >/dev/null 2>&1; dc up -d --wait --scale backend=2 >/dev/null 2>&1
for _ in $(seq 1 20); do login 1 100.80.0.3 "nobody@example.com" "x"; [ "$CODE" = 401 ] && break; sleep 2; done
expect "when the database returns, limiting and logins work again" "$CODE" 401

echo "== old counters are cleaned up"
DBX "INSERT INTO rate_limits VALUES ('old:test', floor(extract(epoch FROM now()))::bigint - 200000, 5), ('fresh:test', floor(extract(epoch FROM now()))::bigint, 5)" >/dev/null
dc restart backend >/dev/null 2>&1; dc up -d --wait --scale backend=2 >/dev/null 2>&1
expect "an expired counter is removed" "$(DBX "SELECT count(*) FROM rate_limits WHERE key = 'old:test'")" 0
expect "a current one is kept" "$(DBX "SELECT count(*) FROM rate_limits WHERE key = 'fresh:test'")" 1

echo "== bad configuration is refused at startup"
OUT=$(dc run --rm -T -e RATE_LIMIT_IP_PER_MIN=0 backend 2>&1); [[ "$OUT" == *"RATE_LIMIT_IP_PER_MIN must be a whole number between 1"* ]] && ok "a zero limit" || bad "zero accepted: $OUT"
OUT=$(dc run --rm -T -e LOGIN_ACCOUNT_WINDOW_SECS=abc backend 2>&1); [[ "$OUT" == *"LOGIN_ACCOUNT_WINDOW_SECS must be a whole number"* ]] && ok "a non-numeric window" || bad "text accepted: $OUT"

if [ $fails -ne 0 ]; then
  echo; echo "  diagnostics: limiter warnings in the backend logs"
  dc logs backend 2>&1 | grep -E "rate limiter unavailable|timed out|could not record" | sed 's/^[^|]*| *//; s/\x1b\[[0-9;]*m//g' | cut -c1-160 | sort | uniq -c | head
fi
echo
[ $fails -eq 0 ] && echo "ALL RATE-LIMIT CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
