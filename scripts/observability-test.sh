#!/usr/bin/env bash
# Checks readiness, request ids, JSON logs and the metrics endpoint on a running stack, and what happens when the
# database goes away.
# Usage: scripts/observability-test.sh
#
# Runs a throwaway copy of the development stack ("acvsobs"). It publishes the same ports as the main
# dev stack, so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

export COMPOSE_PROJECT_NAME=acvsobs LOG_FORMAT=json
T=$(mktemp -d)
trap 'docker compose down -v >/dev/null 2>&1; rm -rf "$T"' EXIT
PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2); export SEED_DEMO_PASSWORD=$PASS
fails=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
inside() { docker compose exec -T backend "$@"; }
code() { inside curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== a healthy stack"
docker compose up -d --build --wait >/dev/null 2>&1 || { echo "FAIL: stack did not start"; exit 1; }
expect "/health answers" "$(code http://localhost:8000/health)" 200
expect "/ready answers" "$(code http://localhost:8000/ready)" 200
inside curl -s http://localhost:8000/ready | grep -q '"ready"' && ok "and says ready" || bad "ready body"
expect "the compose health check uses /ready" "$(docker compose config | grep -c 'localhost:8000/ready')" 1
docker compose port backend 9090 >/dev/null 2>&1 && bad "the metrics port is published to the host" || ok "the metrics port is not published to the host"
curl -s http://localhost:3000/metrics | grep -q 'acvs_' && bad "metrics are visible through the public web server" || ok "and they are not reachable through the web server"
expect "the API port does not expose metrics either" "$(code http://localhost:8000/metrics)" 404

echo "== request ids"
H=$(curl -s -D - -o /dev/null http://localhost:3000/api/v1/ledger/verify | tr -d '\r' | grep -i '^x-request-id:' | cut -d' ' -f2)
[ -n "$H" ] && ok "every response carries X-Request-Id ($H)" || bad "no request id"
H2=$(curl -s -D - -o /dev/null -H 'X-Request-Id: from-the-proxy-1234' http://localhost:3000/api/v1/ledger/verify | tr -d '\r' | grep -i '^x-request-id:' | cut -d' ' -f2)
expect "an id from the proxy is kept" "$H2" from-the-proxy-1234
curl -s -o /dev/null -H 'X-Request-Id: tagged-by-the-test-0001' "http://localhost:3000/api/v1/verify/00000000-0000-0000-0000-000000000000?h=SECRETQUERY"

echo "== logs"
LOGS=$(docker compose logs --no-log-prefix backend 2>&1)
BAD=$(echo "$LOGS" | grep -v '^$' | python3 -c "
import sys, json
bad = 0
for l in sys.stdin:
    try: json.loads(l)
    except ValueError: bad += 1
print(bad)")
expect "every log line is JSON" "$BAD" 0
echo "$LOGS" | grep -q '"request_id":"tagged-by-the-test-0001"\|tagged-by-the-test-0001' && ok "a request id appears in the log of that request" || bad "request id missing from logs"
echo "$LOGS" | grep -q 'route=/api/v1/verify/:id\|"route":"/api/v1/verify/:id"' && ok "the log names the route template" || bad "route missing from logs"
echo "$LOGS" | grep -q '00000000-0000-0000-0000-000000000000\|SECRETQUERY' && bad "a real id or query string reached the log" || ok "no credential id or query string in the log"
echo "$LOGS" | grep -q "$PASS" && bad "the demo password reached the log" || ok "no password in the log"

echo "== metrics"
M=$(inside curl -s http://localhost:9090/metrics)
echo "$M" | grep -q '^acvs_db_up 1' && ok "the database is reported up" || bad "acvs_db_up"
echo "$M" | grep -q 'acvs_http_requests_total{method="GET",route="/api/v1/verify/:id",status="404"}' && ok "requests are counted by route template and status" || bad "request counter"
echo "$M" | grep -q 'acvs_http_request_duration_seconds_bucket' && ok "latency histogram is there" || bad "histogram"
echo "$M" | grep -q '^acvs_ledger_height 0' && ok "ledger gauges" || bad "ledger gauge"
echo "$M" | grep -q '00000000-0000' && bad "an id became a metric label" || ok "no identifier in any label"
echo "$M" | grep -q 'seconds_count' ; echo "$M" | grep -q 'acvs_audit_events_total{action="USER_CREATED"\|acvs_active_sessions' && ok "audit events and sessions are exported" || bad "audit/sessions"

echo "== the database goes away"
docker compose stop postgres >/dev/null 2>&1
sleep 1
expect "/health still says alive" "$(code http://localhost:8000/health)" 200
expect "/ready says not ready (503)" "$(code http://localhost:8000/ready)" 503
inside curl -s http://localhost:9090/metrics | grep -q '^acvs_db_up 0' && ok "metrics report the database down, and still answer" || bad "metrics during outage"
docker compose start postgres >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$(code http://localhost:8000/ready)" = 200 ] && break; sleep 1; done
expect "and /ready recovers by itself" "$(code http://localhost:8000/ready)" 200

echo "== metrics can be turned off"
METRICS_BIND= docker compose up -d --force-recreate --wait backend >/dev/null 2>&1
inside sh -c 'curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/metrics; true' 2>/dev/null | grep -q 000 && ok "with METRICS_BIND empty nothing listens" || bad "metrics still on"

echo
[ $fails -eq 0 ] && echo "ALL OBSERVABILITY CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
