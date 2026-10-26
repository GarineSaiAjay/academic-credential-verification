#!/usr/bin/env bash
# Fails if a GitHub Action is not pinned to a commit SHA, or an image in a Dockerfile, compose file or CI
# `docker run` is not pinned to a digest. Dependabot keeps the pins current (see .github/dependabot.yml).
# Usage: scripts/check-pins.sh
set -uo pipefail
cd "$(dirname "$0")/.."
bad=0
flag() { echo "unpinned: $1"; bad=$((bad + 1)); }

while IFS= read -r l; do flag "$l"; done < <(
  grep -nE '^\s*-?\s*uses:' .github/workflows/*.yml | grep -vE 'uses:\s*\S+@[0-9a-f]{40}(\s|$)')
while IFS= read -r l; do flag "$l"; done < <(
  grep -nE '^\s*FROM\s' backend/Dockerfile frontend/Dockerfile | grep -vE '@sha256:[0-9a-f]{64}' | grep -viE 'FROM\s+scratch')
while IFS= read -r l; do flag "$l"; done < <(
  grep -nE '^\s*image:' docker-compose*.yml .github/workflows/*.yml | grep -vE '@sha256:[0-9a-f]{64}')
while IFS= read -r l; do flag "$l"; done < <(
  grep -nE 'docker run' .github/workflows/*.yml | grep -vE '@sha256:[0-9a-f]{64}')

[ $bad -eq 0 ] && echo "all actions and images are pinned" || { echo "$bad unpinned reference(s)"; exit 1; }
