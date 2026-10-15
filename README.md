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

Demo users are created on first start: `faculty@`, `examcell@`, `registrar@`, `admin@`, `auditor@university.edu`.
The shared password is `SEED_DEMO_PASSWORD` in `.env`. Leave it empty for any real deployment.

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

## Security controls

| Control | Implementation |
|---|---|
| RBAC | Role read from the database on every request (demotion/deactivation is immediate); per-endpoint checks |
| Auth | Argon2id passwords, HS256 JWT bound to a server-side session (logout revokes), 8h expiry, timing-equalised login |
| Replay protection | Every POST needs `X-Nonce` (single use) and `X-Timestamp` (within 60s) |
| Rate limiting | 10 logins/min and 240 requests/min per client IP (in-memory, single instance) |
| Input / WAF-style hardening | Field validation, 16 KB body limit, security headers + strict CSP, parameterised SQL only |
| Secrets | `.env` generated locally and git-ignored; CI generates throwaway secrets |
| CI/CD | GitHub Actions: fmt, clippy `-D warnings`, unit tests, front end build, full-stack smoke test |

## API

Public: `POST /auth/login`, `GET /verify/:id`, `GET /credentials/:id/qr`, `GET /ledger/verify`.
Authenticated: `GET /auth/me`, `POST /auth/logout`, `GET|POST /credentials`, `GET /credentials/:id`,
`POST /credentials/:id/{approve,reject,revoke}`, `GET /keys`, `POST /keys/:role/rotate`, `POST /keys/:id/revoke`,
`GET /ledger/blocks`, `POST /ledger/seal`, `GET /audit`. All under `/api/v1`.

## Limits you should know about

- **The ledger is not a public blockchain.** It is a signed, hash-linked Merkle ledger in your own database. It detects tampering, but whoever controls the DB *and* the university key could rewrite history. To get public-chain guarantees, publish each block's `merkle_root` to a chain (or a timestamping service) after sealing; the data model already carries what you need.
- Rate limiting is per process. Run more than one backend instance and you need a shared store (e.g. Redis).
- This is not a real WAF: for internet exposure put a managed WAF/CDN and TLS in front of nginx.
- The encryption key lives in an environment variable. For higher assurance use a KMS/HSM to wrap the signing keys.
- One signing key per stage, not per person; the audit log records which user triggered each signature.
- No user-management UI yet: users are rows in `users` (create with `auth::hash_password`-compatible Argon2 hashes).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
