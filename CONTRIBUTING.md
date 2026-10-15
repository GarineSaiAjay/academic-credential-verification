# Contributing to ACVS

Thanks for helping out. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) first.
For security problems, do **not** open a public issue; see [SECURITY.md](SECURITY.md).

## Setup

Prerequisites: Docker with Compose, Rust (stable, with `rustfmt` and `clippy`), Node.js 22.

```bash
git clone https://github.com/<your-fork>/academic-credential-verification.git
cd academic-credential-verification
./scripts/gen-env.sh                 # writes .env with random secrets (once)
docker compose up -d postgres        # Postgres on 127.0.0.1:55432
```

Then run the backend (`cargo run` in `backend/`, with `DATABASE_URL`, `JWT_SECRET`, `ENCRYPTION_KEY` set)
and the front end (`npm install && npm run dev` in `frontend/`, which proxies `/api` to :8000).
Never commit `.env` or any real secret.

## Branch naming

Branch from `main` using `<type>/<short-description>`:

`feat/qr-download`, `fix/nonce-replay-window`, `docs/contributing`, `chore/bump-sqlx`, `test/ledger-seal`

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <summary>`

- Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`
- Imperative mood, summary under 72 characters, explain the *why* in the body when it isn't obvious.
- Example: `fix(auth): reject expired sessions on logout`

## Running tests

These are the same checks CI runs; please make them pass before opening a PR.

```bash
# backend (from backend/)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# frontend (from frontend/)
npm ci && npm run build

# full stack (from the repo root)
docker compose up -d --build --wait
./scripts/smoke.sh http://localhost:3000
```

## Opening a pull request

1. Fork the repo and create a branch as above.
2. Keep the PR focused: one logical change. Add or update tests and docs.
3. Push and open a PR against `main`; fill in the PR template and link the issue (`Closes #123`).
4. Wait for CI to go green.

## What review looks like

- A maintainer reviews, usually within a few days. Feel free to ping after a week.
- Expect comments on correctness, security (this project signs credentials), tests, and clarity.
- Address feedback with new commits; the PR is squash-merged, so history stays clean.
- Changes touching signing, auth, or the ledger get extra scrutiny.
