#!/usr/bin/env bash
# End-to-end test of the production stack (docker-compose.prod.yml): TLS, WAF, client-IP handling,
# closed ports, and the full smoke suite through the whole chain. Usage: scripts/prod-test.sh
#
# Runs a throwaway compose project ("acvsprod") with its own volumes, DOMAIN=localhost (Caddy then
# issues a certificate from its own local CA, so no public DNS is needed) and the demo users from
# deploy/test-seed.yml. Needs host ports 80 and 443 free, so stop anything else using them.
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

export COMPOSE_PROJECT_NAME=acvsprod COMPOSE_FILE=docker-compose.prod.yml:deploy/test-seed.yml
export DOMAIN=localhost BOOTSTRAP_ADMIN_EMAIL= BOOTSTRAP_ADMIN_PASSWORD=
SEED_DEMO_PASSWORD=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2); export SEED_DEMO_PASSWORD
[ -n "$SEED_DEMO_PASSWORD" ] || { echo ".env needs SEED_DEMO_PASSWORD (scripts/gen-env.sh sets it)" >&2; exit 1; }
T=$(mktemp -d); fails=0
cleanup() {
  [ $fails -ne 0 ] && docker compose logs --tail 40 2>&1 | sed 's/^/    log: /' | head -200
  docker compose down -v >/dev/null 2>&1; rm -rf "$T"
}
trap cleanup EXIT

ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
C() { curl -s --cacert "$T/root.crt" "$@"; }

echo "== start the production stack"
docker compose down -v >/dev/null 2>&1 # never reuse leftovers from an earlier run
docker compose up -d --build --wait >/dev/null 2>&1 && ok "all services healthy" || { bad "stack did not become healthy"; exit 1; }
for _ in $(seq 1 30); do docker compose cp edge:/data/caddy/pki/authorities/local/root.crt "$T/root.crt" >/dev/null 2>&1 && break; sleep 1; done
[ -s "$T/root.crt" ] && ok "obtained the edge's local CA certificate" || { bad "no CA certificate"; exit 1; }

echo "== exposure"
published=$(docker compose ps --format json | python3 -c '
import sys, json
text = sys.stdin.read().strip()
# Older compose prints one JSON object per line, newer prints a single array.
rows = json.loads(text) if text.startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip()]
out = []
for row in rows:
    for p in row.get("Publishers") or []:
        if p.get("PublishedPort") and p.get("Protocol", "tcp") == "tcp":
            out.append(row["Service"] + ":" + str(p["PublishedPort"]))
print(" ".join(sorted(set(out))))')
expect "only the edge publishes ports (80, 443)" "$published" "edge:443 edge:80"
for p in 55432 8000 3000 8080 2019; do
  (exec 3<>/dev/tcp/127.0.0.1/"$p") 2>/dev/null && bad "port $p is reachable from the host" || ok "port $p is closed on the host"
done

echo "== TLS"
expect "HTTPS serves the app (certificate verifies)" "$(C -o /dev/null -w '%{http_code}' https://localhost/)" 200
expect "HTTP redirects to HTTPS" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://localhost/)" "308 https://localhost/"
expect "HTTP/2 negotiated" "$(C -o /dev/null -w '%{http_version}' https://localhost/)" 2
python3 -W ignore - "$T/root.crt" <<'PY' > "$T/tls.out"
import socket, ssl, sys
def attempt(lo, hi):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(sys.argv[1])
    try:
        ctx.minimum_version, ctx.maximum_version = lo, hi
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return "unsupported-by-client"
    try:
        with socket.create_connection(("localhost", 443), timeout=10) as s, ctx.wrap_socket(s, server_hostname="localhost") as t:
            return t.version()
    except ssl.SSLError as e:
        # Only a protocol-version alert from the server counts; other failures prove nothing.
        return "refused" if "PROTOCOL_VERSION" in str(e) else "inconclusive: " + str(e)
    except OSError as e:
        return "inconclusive: " + str(e)
V = ssl.TLSVersion
print("tls13", attempt(V.TLSv1_3, V.TLSv1_3))
print("tls12", attempt(V.TLSv1_2, V.TLSv1_2))
print("tls11", attempt(V.TLSv1, V.TLSv1_1))
PY
expect "TLS 1.3 accepted" "$(grep '^tls13' "$T/tls.out" | cut -d' ' -f2)" TLSv1.3
expect "TLS 1.2 accepted" "$(grep '^tls12' "$T/tls.out" | cut -d' ' -f2)" TLSv1.2
v11=$(grep '^tls11' "$T/tls.out" | cut -d' ' -f2-)
case "$v11" in
  refused) ok "TLS 1.1 and older refused by the server" ;;
  TLSv1*) bad "TLS 1.1 or older was accepted ($v11)" ;;
  *) echo "  skip TLS 1.1 check (could not attempt it from here: $v11)" ;;
esac

echo "== response headers"
C -D "$T/h.root" -o /dev/null https://localhost/; C -D "$T/h.api" -o /dev/null https://localhost/api/v1/ledger/verify
for f in root api; do
  grep -qi '^strict-transport-security: max-age=31536000' "$T/h.$f" && ok "HSTS on $f response" || bad "no HSTS on $f response"
  grep -qi '^server:' "$T/h.$f" && bad "Server header leaked on $f response" || ok "no Server header on $f response"
done
grep -qi '^content-security-policy:' "$T/h.root" && ok "CSP still present on the page" || bad "CSP missing"

echo "== WAF (OWASP Core Rule Set)"
expect "XSS in query string blocked" "$(C -o /dev/null -w '%{http_code}' 'https://localhost/?q=%3Cscript%3Ealert(1)%3C/script%3E')" 403
expect "SQL injection in API query blocked" "$(C -o /dev/null -w '%{http_code}' "https://localhost/api/v1/verify/1?x=1%27%20OR%20%271%27=%271")" 403
expect "scanner user agent blocked" "$(C -o /dev/null -w '%{http_code}' -A 'sqlmap/1.7' https://localhost/)" 403
expect "SQL injection in JSON body blocked" "$(C -o /dev/null -w '%{http_code}' -X POST https://localhost/api/v1/auth/login -H 'Content-Type: application/json' -d "{\"email\":\"a@b.co' OR 1=1 --\",\"password\":\"x\"}")" 403
t=$(C -o /dev/null -w '%{http_code}' --path-as-is 'https://localhost/%2e%2e/%2e%2e/etc/passwd'); case "$t" in 400|403|404) ok "path traversal refused ($t)" ;; *) bad "path traversal got $t" ;; esac
expect "a normal API request passes" "$(C -o /dev/null -w '%{http_code}' https://localhost/api/v1/ledger/verify)" 200
expect "a normal login request passes the WAF" "$(C -o /dev/null -w '%{http_code}' -X POST https://localhost/api/v1/auth/login -H 'Content-Type: application/json' -d '{"email":"nobody@example.com","password":"wrong-password-1"}')" 401
expect "oversized body refused at the edge" "$(python3 -c 'print("x"*40000)' | C -o /dev/null -w '%{http_code}' -X POST https://localhost/api/v1/auth/login -H 'Content-Type: application/json' --data-binary @-)" 413

echo "== client address handling"
login() { C -X POST https://localhost/api/v1/auth/login -H 'Content-Type: application/json' "$@" -d "{\"email\":\"admin@university.edu\",\"password\":\"$SEED_DEMO_PASSWORD\"}" | j "d['token']"; }
login -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Real-IP: 203.0.113.10' >/dev/null
TOKEN=$(login)
IPS=$(C 'https://localhost/api/v1/audit?limit=10' -H "Authorization: Bearer $TOKEN" | j "sorted({l['details']['ip'] for l in d['logs'] if l['action']=='LOGIN'})")
echo "$IPS" | grep -q '203.0.113' && bad "a client-supplied address was trusted: $IPS" || ok "forged X-Forwarded-For / X-Real-IP ignored"
echo "$IPS" | grep -qE "172\.29\.250\.(10|11|12)" && bad "audit log shows an internal proxy address: $IPS" || ok "audit log records the real client address, not a proxy ($IPS)"
# A client that reaches the API without going through the web container is not a trusted proxy, so its header is
# ignored too. Here that is a request from inside the backend container itself (the address 127.0.0.1).
docker compose exec -T backend curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -H 'X-Forwarded-For: 198.51.100.77' \
  -d "{\"email\":\"admin@university.edu\",\"password\":\"$SEED_DEMO_PASSWORD\"}" http://localhost:8000/api/v1/auth/login
IPS=$(C 'https://localhost/api/v1/audit?limit=10' -H "Authorization: Bearer $TOKEN" | j "sorted({l['details']['ip'] for l in d['logs'] if l['action']=='LOGIN'})")
echo "$IPS" | grep -q '198.51.100' && bad "X-Forwarded-For from an untrusted peer was believed: $IPS" || ok "X-Forwarded-For from a peer that is not the web container is ignored"
echo "$IPS" | grep -q '127.0.0.1' && ok "and the audit log records the connecting address instead" || bad "expected 127.0.0.1 in $IPS"
OUT=$(docker compose run --rm -T -e TRUST_PROXY=true -e TRUSTED_PROXIES= backend ./server 2>&1); echo "$OUT" | grep -q 'TRUSTED_PROXIES' && ok "the retired TRUST_PROXY=true alone is refused at startup" || bad "TRUST_PROXY=true accepted: $OUT"
OUT=$(docker compose run --rm -T -e TRUSTED_PROXIES=10.0.0.0/40 backend ./server 2>&1); echo "$OUT" | grep -q 'prefix length' && ok "a malformed TRUSTED_PROXIES is refused at startup" || bad "bad range accepted: $OUT"

echo "== the application, end to end through TLS + WAF"
# The smoke suite uses the whole per-IP login allowance, and limit counters live in the database (they survive
# restarts), so start it from empty counters.
docker compose exec -T postgres psql -U acvs -d acvs -qAt -c "DELETE FROM rate_limits" >/dev/null 2>&1
docker compose restart backend >/dev/null 2>&1 && docker compose up -d --wait >/dev/null 2>&1 && ok "backend restarted cleanly" || bad "backend did not come back"
CURL_CA_BUNDLE="$T/root.crt" ./scripts/smoke.sh https://localhost > "$T/smoke.out" 2>&1
tail -3 "$T/smoke.out" | sed 's/^/    /'
grep -q 'ALL CHECKS PASSED' "$T/smoke.out" && ok "scripts/smoke.sh passes through the full chain ($(grep -c '^  ok' "$T/smoke.out") checks)" || { bad "smoke test failed"; grep FAIL "$T/smoke.out" | head; }

echo
[ $fails -eq 0 ] && echo "ALL PRODUCTION CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
