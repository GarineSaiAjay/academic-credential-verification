# ACVS - Academic Credential Verification

Tamper-evident academic credentials. Four stages sign each credential with their own Ed25519 key
(Faculty -> Exam Cell -> Registrar -> University). Anyone can verify one, without an account, by ID or QR code.

Rust (Axum, Tokio, sqlx) + PostgreSQL + a small React front end behind nginx.

## Run

```bash
./scripts/gen-env.sh          # writes .env with random secrets (once)
docker compose up -d --build
open http://localhost:3000
```

This is the **development** stack: plain HTTP, no WAF, demo users. For a real deployment use the
[production stack](#production-deployment-tls--waf) below.

Demo users are created on first start: `faculty@`, `examcell@`, `registrar@`, `admin@`, `auditor@university.edu`.
The shared password is `SEED_DEMO_PASSWORD` in `.env`. Leave it empty for any real deployment.

**Real deployment: create the first admin.** Leave `SEED_DEMO_PASSWORD` empty and set `BOOTSTRAP_ADMIN_EMAIL` and
`BOOTSTRAP_ADMIN_PASSWORD` (12-128 characters) in `.env`. On first start, while the `users` table is empty, the backend
creates that account as `university_admin`. It never runs again once any user exists, and it takes precedence over the
demo seed. Remove `BOOTSTRAP_ADMIN_PASSWORD` from `.env` after the first start, then create everyone else on the
**Users** page. If the backend starts with no users and neither variable set, it logs a warning.

Verify everything works (end-to-end checks against the running stack):

```bash
./scripts/smoke.sh http://localhost:3000
```

Local dev: `docker compose up -d postgres` (published on `127.0.0.1:55432`), then run `cargo run` in `backend/`
with `DATABASE_URL`, `JWT_SECRET`, `ENCRYPTION_KEY` set, and `npm run dev` in `frontend/` (proxies `/api` to :8000).

## How it works

| Stage | Role that signs | Result |
|---|---|---|
| Create | `faculty` (signs automatically) | `pending_exam_cell` |
| Sign | `exam_cell` | `pending_registrar` |
| Sign | `registrar` | `pending_university` |
| Sign | `university_admin` (university key) | `issued` |

Any stage role can also reject. `university_admin` can revoke an issued credential.

- **Content hash**: SHA-256 over canonical JSON (sorted keys) of the credential fields plus its ID.
- **Signatures**: each stage signs `ACVS-APPROVAL-v1|id|stage|hash` (binds credential, stage and content). A stage will not co-sign if earlier signatures or the hash no longer verify.
- **Public verification** (`GET /api/v1/verify/:id`) recomputes everything from stored data: hash, every signature, signing-key status, stage order, ledger proof. Verdicts: `VALID`, `PENDING`, `REJECTED`, `REVOKED`, `INVALID`.
- **QR code** encodes `/#/verify/<id>/<first 16 hex of hash>`; the verify page flags a QR whose hash prefix no longer matches.
- **Ledger**: `university_admin` seals all issued, un-anchored credentials into a block: Merkle root (0x00/0x01 domain-separated, odd nodes promoted), hash-linked to the previous block, signed with the university key. `GET /api/v1/ledger/verify` re-verifies the whole chain; each credential carries a Merkle inclusion proof.
- **Key management**: one active key per stage (enforced by a unique index). *Rotate* retires the old key (old signatures stay valid). *Revoke* marks a key compromised: everything it signed verifies as `INVALID` until the stage key is rotated and credentials re-issued. Private keys are stored AES-256-GCM encrypted under `ENCRYPTION_KEY`.
- `approvals`, `blocks` and `audit_logs` are append-only (database triggers reject UPDATE/DELETE).
- **User management**: `university_admin` creates users, changes roles, deactivates/reactivates accounts and resets passwords
  (Users page). Deactivation and password reset sign the user out everywhere; role changes apply on the next request.
  Admins cannot change their own role or active state, and the last active admin can never be demoted or deactivated
  (enforced under a row lock, so two admins cannot lock each other out). Every user can change their own password
  (Account page: click your email in the header), which signs out their other sessions. Passwords are 12-128 characters.
  All of this is written to the audit log; passwords never are.

## Production deployment (TLS + WAF)

`docker-compose.prod.yml` puts the application behind a TLS edge and a web application firewall:

```
internet -> edge (Caddy: TLS, HSTS)  ->  waf (OWASP Core Rule Set)  ->  frontend (nginx)  ->  backend  ->  postgres
            ports 80, 443 only          blocks injection, XSS, scanners    SPA                API
```

1. Point a DNS record for your host name at the server and open ports 80 and 443 (80 is needed for certificate issuance
   and the redirect to HTTPS).
2. In `.env` set `DOMAIN=credentials.example.edu`, leave `SEED_DEMO_PASSWORD` out, and set `BOOTSTRAP_ADMIN_EMAIL` /
   `BOOTSTRAP_ADMIN_PASSWORD` for the first admin (see above). `./scripts/gen-env.sh` creates the secrets.
3. `docker compose -f docker-compose.prod.yml up -d --build`

Caddy obtains and renews the certificate by itself (Let's Encrypt) and keeps it in the `caddy_data` volume, so keep that
volume. It redirects HTTP to HTTPS, speaks TLS 1.2/1.3 and HTTP/2, sends `Strict-Transport-Security` (one year, without
`includeSubDomains` or `preload`: add them yourself only if every subdomain is HTTPS), hides the `Server` header, and
refuses bodies over 32 KB. Only the edge publishes ports; the database, API, web server and WAF are reachable only inside
the compose network. QR codes use `https://DOMAIN`.

**WAF.** The OWASP Core Rule Set (ModSecurity v3 on nginx, image pinned in the compose file) runs at paranoia level 1.
Set `WAF_MODE=DetectionOnly` to log without blocking while you check for false positives, and raise `WAF_PARANOIA`
(up to 4) for stricter, noisier rules. Blocked requests are logged as JSON on the `waf` container (`docker compose -f
docker-compose.prod.yml logs waf`). The full smoke suite passes through it at level 1; if you raise the level, re-run
`scripts/prod-test.sh`.

**Client addresses.** Rate limiting and the audit log need the real client IP. Caddy replaces any client-supplied
`X-Forwarded-For` with the connecting address, the WAF trusts only the edge's fixed address (`172.29.250.10`), and the web
container trusts only the WAF's (`172.29.250.11`; see `deploy/real-ip.conf`). Headers a client invents are ignored. The
compose network uses the fixed subnet `172.29.250.0/24`; change it everywhere if that clashes with your network.

`scripts/prod-test.sh` checks all of this on a throwaway copy of the stack (TLS versions, redirect, HSTS, closed ports,
attack payloads blocked, forged headers ignored) and runs the whole smoke suite through TLS and the WAF. It uses
`DOMAIN=localhost`, for which Caddy issues a certificate from its own local CA, so it needs host ports 80 and 443 free.
It does not talk to Let's Encrypt, so first-time issuance on your real domain is the one thing it cannot prove: watch
`docker compose -f docker-compose.prod.yml logs edge` on first start.

## Backing up and recovering the signing keys

Private signing keys live in the database, encrypted under `ENCRYPTION_KEY`. **If `ENCRYPTION_KEY` is lost, they cannot be
opened and nothing can be signed.** Credentials already issued still verify, because verification needs only public keys.
Take a key backup once after setup and again after every key rotation or revocation. It is protected by a passphrase you
choose, separate from `ENCRYPTION_KEY`, and holds only the active keys.

```bash
export KEY_BACKUP_PASSPHRASE='a long passphrase you will not lose'   # at least 16 characters
umask 077
docker compose exec -T -e KEY_BACKUP_PASSPHRASE backend ./server key-backup > acvs-keys.backup
```

Keep the file and the passphrase **apart from each other, from `.env` and from database backups**: anyone holding the file and
the passphrase can sign as your university. To recover after losing `ENCRYPTION_KEY`:

```bash
# 1. put a NEW random ENCRYPTION_KEY in .env (openssl rand -hex 32). The old backend now refuses to start,
#    and says why.
# 2. re-encrypt the backed-up keys under it (add --dry-run first to preview; nothing is saved):
docker compose run --rm -T -e KEY_BACKUP_PASSPHRASE backend ./server key-restore < acvs-keys.backup
# 3. start normally
docker compose up -d
```

Restore keeps the same signing keys, so existing credentials keep verifying. It also rebuilds the keys on an empty database,
and it refuses to overwrite a key whose public half differs from the backup. `scripts/recovery-test.sh` runs this whole
scenario (it is part of CI). This protects the keys only: you still need regular database backups (`pg_dump`) for everything else.

## Security controls

| Control | Implementation |
|---|---|
| RBAC | Role read from the database on every request (demotion/deactivation is immediate); per-endpoint checks |
| Auth | Argon2id passwords, HS256 JWT bound to a server-side session (logout revokes), 8h expiry, timing-equalised login |
| Replay protection | Every POST needs `X-Nonce` (single use) and `X-Timestamp` (within 60s) |
| Rate limiting | 10 logins/min and 240 requests/min per client IP (in-memory, single instance) |
| Input / WAF | Field validation, 16 KB body limit, security headers + strict CSP, parameterised SQL only; production stack adds the OWASP Core Rule Set WAF |
| Transport | Production stack: automatic HTTPS (TLS 1.2/1.3), HTTP to HTTPS redirect, HSTS; only ports 80/443 exposed |
| Secrets | `.env` generated locally and git-ignored; CI generates throwaway secrets |
| CI/CD | GitHub Actions: fmt, clippy `-D warnings`, unit tests, front end build, full-stack smoke test |

## API

Public: `POST /auth/login`, `GET /verify/:id`, `GET /credentials/:id/qr`, `GET /ledger/verify`.
Authenticated: `GET /auth/me`, `POST /auth/logout`, `GET|POST /credentials`, `GET /credentials/:id`,
`POST /credentials/:id/{approve,reject,revoke}`, `GET /keys`, `POST /keys/:role/rotate`, `POST /keys/:id/revoke`,
`GET /ledger/blocks`, `POST /ledger/seal`, `GET /audit`, `POST /auth/password`.
`university_admin` only: `GET|POST /users`, `POST /users/:id/{role,active,password}`. All under `/api/v1`.

## Limits you should know about

- **The ledger is not a public blockchain.** It is a signed, hash-linked Merkle ledger in your own database. It detects tampering, but whoever controls the DB *and* the university key could rewrite history. To get public-chain guarantees, publish each block's `merkle_root` to a chain (or a timestamping service) after sealing; the data model already carries what you need.
- Rate limiting is per process. Run more than one backend instance and you need a shared store (e.g. Redis).
- The built-in WAF is the generic OWASP rule set on a single host. It does not absorb DDoS traffic or replace a managed WAF/CDN; for large-scale exposure put one in front of the edge.
- The encryption key lives in an environment variable. For higher assurance use a KMS/HSM to wrap the signing keys. Losing it is recoverable only if you made a key backup (see above).
- One signing key per stage, not per person; the audit log records which user triggered each signature.
- No account lockout, MFA or self-service password *reset* (forgot password); an admin can reset a password for a user.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
