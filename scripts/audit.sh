#!/usr/bin/env bash
# Runs the same dependency, secret and image checks as the "audit" and "images" CI jobs.
# Usage: scripts/audit.sh     (needs Docker, npm and cargo-audit: cargo install cargo-audit --locked)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Rust dependencies"; (cd backend && cargo audit --deny warnings)
echo "== npm dependencies"; (cd frontend && npm audit --audit-level=high)
echo "== secrets in the repository and its history"
docker run --rm -v "$PWD":/repo zricethezav/gitleaks:v8.30.0 detect --source /repo --config /repo/.gitleaks.toml --no-banner --redact
echo "== images built by this project"
docker build -q -t acvs-backend backend >/dev/null
docker build -q -t acvs-frontend frontend >/dev/null
for img in acvs-backend acvs-frontend; do
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.69.3 image --quiet \
    --severity HIGH,CRITICAL --ignore-unfixed --scanners vuln,secret --exit-code 1 "$img"
done
echo
echo "ALL AUDIT CHECKS PASSED"
