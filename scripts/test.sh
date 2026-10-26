#!/usr/bin/env bash
# Runs the fast tests: the Rust unit and API tests (against a throwaway Postgres) and the front-end tests.
# Usage: scripts/test.sh            (needs Docker for the database, plus cargo and npm)
# The slower end-to-end scripts (smoke.sh, auth-test.sh, ...) start whole stacks and are run separately.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME=acvs-testdb-$$
PORT=${TEST_DB_PORT:-55432}
if [ -z "${DATABASE_URL:-}" ]; then
  docker run -d --rm --name "$NAME" -e POSTGRES_PASSWORD=test -p "$PORT:5432" postgres:16-alpine >/dev/null
  trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT
  until docker exec "$NAME" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
  sleep 2 # the server restarts once while it initialises
  export DATABASE_URL=postgres://postgres:test@localhost:$PORT/postgres
fi

echo "== backend"
(cd backend && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
echo "== frontend"
(cd frontend && { [ -d node_modules ] || npm ci; } && npm test && npm run build)
echo
echo "ALL FAST TESTS PASSED"
