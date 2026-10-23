#!/usr/bin/env bash
# Generates .env with fresh random secrets. Refuses to overwrite an existing file.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -e .env ] && { echo ".env already exists; delete it first to regenerate" >&2; exit 1; }
cat > .env <<ENV
POSTGRES_PASSWORD=$(openssl rand -hex 16)
JWT_SECRET=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -hex 32)
# Demo accounts (faculty@, examcell@, registrar@, admin@, auditor@university.edu) are created on first start.
# Remove this value for any real deployment and set BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD instead
# (creates the first university_admin while the users table is empty; remove the password after first start).
SEED_DEMO_PASSWORD=$(openssl rand -hex 6)
ENV
echo "wrote .env (demo password is SEED_DEMO_PASSWORD in that file)"
