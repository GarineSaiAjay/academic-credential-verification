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
- **Rejection and revocation are signed events**, not just a status column. A reject is signed by the key of the stage that rejected; a revoke by the university key. The signature covers the credential's content hash, the reason and the time, and the event is append-only. Verification trusts the event: a revoked credential whose status is edited back to `issued` still reads `REVOKED`, a `revoked` status with no valid event behind it reads `INVALID`, and an edited reason breaks the signature. A status that is already final cannot be changed again. Credentials rejected or revoked before this existed get their event signed by the server on the next start (marked "added later"); that signature vouches for what the status column said at that moment.
- **Re-issuing.** A revoked, rejected or invalid credential (for example, signed by a stage key that was later revoked) can be replaced: a faculty member presses **Re-issue** (`POST /credentials/:id/reissue`, optionally with corrected fields). This creates a *new* credential, because every signature is bound to a credential's id and hash, and it goes through all four stages again. The new credential carries the old one's id inside its signed content hash, so the link cannot be edited. Verifying the old credential (for example from a printed QR code) shows "replaced by ..." and the replacement's current verdict. Only one live replacement can exist at a time; a valid or pending credential must be revoked first. Fields left out are copied from the old credential only while its stored content still passes its integrity check.
- **Personal signatures.** The stage keys live on the server, so they prove that *a holder of the role* approved, not *who*. A person can register a **passkey or hardware security key** (Account page); it is a WebAuthn credential whose private half never leaves their device, so neither the server nor an administrator can sign as them. Each approval keeps its stage-key signature and can carry the approver's own signature over the same approval message. The authenticator's raw output is stored unchanged, so anyone can re-verify it with only the public key (`GET /verify/:id` returns everything needed; `scripts/webauthn_sim.py check` and the README section below show how). A retired key (replaced or lost) keeps what it signed valid; a key reported compromised makes what it signed `INVALID`. Set `REQUIRE_PERSONAL_SIGNATURES=true` to make a personal signature mandatory on every approval; the faculty member adds theirs with **Add my personal signature**, because their approval is made by creating the credential. Credentials approved before the policy was switched on stay valid.
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

## Accounts, sessions and two-factor sign-in

**Sessions.** Every sign-in is a server-side session. *Account → Where you are signed in* lists your live sessions (device, address, time) and signs out any of them or all the others; an administrator can sign a user out everywhere from the Users page. Sessions that expired or were revoked more than a week ago are deleted automatically. Changing your password, turning two-factor sign-in on or off, or being reset by an administrator ends your other sessions.

**Passwords.** 12-128 characters, not on a built-in list of common passwords, not one repeated character and not built from the account's email address. This is not a breached-password database. Repeated failures throttle the account (see *Request limits*).

**Forgot your password.** There is no mail server in this stack, so an administrator issues a one-time reset link (Users → *Reset link*) and hands it to the person. The link is valid for one hour, works once, a newer link cancels an older one, and only a hash of it is stored. Using it sets the password and signs the account out everywhere; it does not bypass a second factor.

**Two-factor sign-in.** Anyone can turn on authenticator-app codes (TOTP: Google Authenticator, Authy, 1Password and the like) under *Account*. They get ten single-use recovery codes, shown once. A code works once, a wrong guess costs five tries per five minutes, and the secret is encrypted with `ENCRYPTION_KEY` (and moves with it in a rotation). Set `REQUIRE_MFA_ROLES` (for example `registrar,exam_cell,university_admin`) to make roles use it: until they have set it up, their session can do nothing else, and they cannot turn it off. A lost device is reset by an administrator (Users → *Reset 2FA*); if no administrator can sign in, run `docker compose exec backend ./server totp-reset someone@example.edu`.

## Client addresses behind a proxy

Rate limits and the audit log use the client's address. The backend believes `X-Forwarded-For` only when the connection comes from an address in `TRUSTED_PROXIES` (comma-separated addresses or ranges such as `172.29.250.12` or `10.0.0.0/8`). Then it reads the header from the right, skipping trusted proxies, and takes the first address that is not one: whatever the client wrote further left is ignored, so a client cannot pick its own address even if a proxy appends instead of replacing. Anyone else connecting, or a malformed header, gets the connecting address. With `TRUSTED_PROXIES` unset the header is ignored entirely. The old `TRUST_PROXY=true` is refused at startup because it trusted whoever connected. The development compose file trusts loopback and the private ranges Docker uses; the production one trusts only the web container's fixed address.

## Request limits

Limits are counted in Postgres (table `rate_limits`), so they are exact across any number of backend instances and survive restarts, with no extra service to run. A small in-memory check in front sheds floods without touching the database, and if the database is slow or down the limiter falls back to counting per process instead of stalling requests.

| Limit | Default | Setting |
|---|---|---|
| Anonymous requests per client address per minute (the public verification page shares this) | 240 | `RATE_LIMIT_IP_PER_MIN` |
| Signed-in requests per **user** per minute (people behind one office address do not share a budget) | 600 | `RATE_LIMIT_USER_PER_MIN` |
| Login attempts per client address per minute | 10 | `LOGIN_IP_PER_MIN` |
| Failed logins per **account**, from any address, per window | 20 per 900 s | `LOGIN_ACCOUNT_FAILURES`, `LOGIN_ACCOUNT_WINDOW_SECS` |

A refused request gets HTTP 429 with a `Retry-After` header. A token is only used to pick a user's bucket after its signature is checked, so an invented token earns no bucket of its own. The per-account throttle also applies to emails that do not exist, so it never reveals which accounts are registered, and throttled attempts are audit-logged as `LOGIN_THROTTLED` (without the password). Start several instances with `docker compose up -d --scale backend=2`; first-start initialisation is serialised so they can boot together. `scripts/ratelimit-test.sh` proves all of this with two instances on one database (also a CI job).

## Rotating `ENCRYPTION_KEY`

Rotate the key that encrypts the signing keys at rest on a schedule, or whenever someone who had access to it leaves. It needs no downtime and loses nothing.

```bash
# 1. Make a new key and keep the old one for now. In .env:
#      ENCRYPTION_KEY=<new key>            (openssl rand -hex 32)
#      ENCRYPTION_KEY_PREVIOUS=<old key>
docker compose up -d                        # reads data under either key, writes under the new one

# 2. Re-encrypt every stored signing key under the new key (add --dry-run to preview; nothing is saved).
docker compose run --rm -T backend ./server key-rewrap

# 3. Remove ENCRYPTION_KEY_PREVIOUS from .env and restart. Now destroy the old key.
docker compose up -d
```

Every stored key carries a small header naming the key that sealed it, so the server knows which key to use. `key-rewrap` moves **all** stored signing keys, including retired and revoked ones and ones written before the header existed, in a single transaction: either every key moves or none does, and it refuses (changing nothing) if any key cannot be opened. Until it has run, the server logs a warning on every start. A server started with only the new key refuses to start and says to keep the old one in `ENCRYPTION_KEY_PREVIOUS`. The passphrase-protected key backup is independent of this key and unaffected. `JWT_SECRET` is a separate secret: changing it signs everyone out. `scripts/rotation-test.sh` runs this whole procedure (also a CI job).

## Anchoring the ledger to an external timestamp authority

The ledger on its own is only as trustworthy as the database and the university key: whoever controls both could rewrite
history and re-sign it. To close that gap, set `TSA_URL` and `TSA_CA_FILE` and every sealed block's hash is also sent to
an independent [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) time-stamping authority (TSA), which returns a token,
signed with its own key, saying "this digest existed at this time". Each block hash covers the previous one, so a token for
block N pins the whole chain up to N; changing anything earlier would contradict a signature the university does not hold.

```bash
# 1. Put the TSA's root certificate in deploy/tsa/ca.pem (from the TSA's own site, over HTTPS; check its fingerprint).
# 2. In .env:
TSA_URL=https://freetsa.org/tsr
TSA_CA_FILE=/etc/acvs/tsa/ca.pem
# 3. docker compose up -d
```

- A token is stored only after `openssl ts -verify` accepts it against your CA file, so a reply signed by anyone else is
  rejected. It is also checked at the time stamped in it, so it stays valid after the TSA's certificate expires.
- Timestamping happens right after sealing and is retried every `TSA_INTERVAL_SECS` (default 300) for blocks the TSA could
  not stamp, for example during an outage. Admins can also press **Timestamp pending blocks now** on the Ledger page
  (`POST /ledger/timestamp`). A block without a token is simply "pending"; credentials in it stay `VALID`.
- Tokens are immutable in the database (`block_timestamps`). The ledger page, the credential verification page
  and `GET /ledger/verify` show them; `GET /ledger/blocks/:n/timestamp` re-verifies one and returns it.
- **Anyone can check it without trusting this server**, using only the TSA's certificate:

```bash
curl -O https://HOST/api/v1/ledger/blocks/1/timestamp.tsq -O https://HOST/api/v1/ledger/blocks/1/timestamp.tsr
openssl ts -verify -queryfile timestamp.tsq -in timestamp.tsr -CAfile tsa-ca.pem     # Verification: OK
```

  The request holds the block hash (`GET /ledger/blocks` lists it; it is recomputable from the block's fields), and
  OpenSSL confirms the TSA signed exactly that digest with a certificate chaining to its root.
- Limits: this proves the chain existed by the stamped time; it does not make the ledger a public blockchain. You trust the TSA
  (use more than one if that worries you), and revocation (CRL/OCSP) of the TSA's key is not checked. The backend image
  ships the `openssl` command line for this. `TSA_URL` may be `http://` because the reply is signed; use `https://` anyway.
- `scripts/timestamp-test.sh` runs the whole flow against a throwaway authority that can answer correctly, with an untrusted
  key, with garbage, or not at all (also run in CI).

## Personal signatures (passkeys / security keys)

Turn this on when you need to prove *which person* approved a credential, not only that someone holding the role did.

1. Each approver opens **Account -> My security keys** and adds a passkey or security key (YubiKey, Touch ID, Windows Hello, a phone). The browser needs HTTPS (or `localhost`); the production stack provides it. **Who may add a key is restricted, because otherwise anyone who learned a password could add a key of their own and approve as that person:** a person's *first* key needs only a login (or an administrator's go-ahead if `REQUIRE_ADMIN_ENROLLMENT=true`); *another* key must be approved by one of their existing keys; and someone with no active key who has had one before (lost, retired or revoked) needs an administrator to open a 24-hour, single-use enrolment window (**Users -> Allow key enrolment**). Every registration and every window is audit-logged.
2. Approve as usual: the page asks for the key and signs with it. With `REQUIRE_PERSONAL_SIGNATURES=true` in `.env` this is mandatory: an approval without one is refused, and an approval is refused while an earlier approver's personal signature is still missing (faculty add theirs from the credential page).
3. Verification shows a "Personal signature" column and a `personal_signatures_ok` check. The public page shows only a key fingerprint, never a name or email; signed-in staff can see who approved.

The relying-party id is the host of `PUBLIC_BASE_URL` (`WEBAUTHN_RP_ID` may widen it to a parent domain). Changing the domain later does not break old signatures, because each one stores the site it was made for. Keys are P-256 (ES256); the server stores only the public key.

**Check one yourself, without trusting the server.** In the `GET /api/v1/verify/<id>` response, for each signature with a `personal` object: the signature is ECDSA-P256 over `authenticator_data || SHA-256(client_data_json)`, verifiable with the DER `public_key`; the `challenge` inside `client_data_json` must equal `base64url(SHA-256("ACVS-APPROVAL-v1|<id>|<stage>|<credential_hash>"))`; and the first 32 bytes of `authenticator_data` must be `SHA-256(rp_id)` with the user-present and user-verified flags (0x05) set. `python3 scripts/webauthn_sim.py check <saved verify response>` does exactly this with plain `openssl`.

**Tests.** `scripts/personal-sig-test.sh` runs the whole flow with a software authenticator (also against the production stack with `MODE=prod`); `e2e/browser.mjs` drives the real UI in real Chrome with Chrome's virtual authenticator; `scripts/verify-race-test.py` guards a fix that made verification read a credential, its approvals and its final event in one database snapshot.

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
scenario (it is part of CI). This protects the keys only: everything else needs the database backups described next.

## Backing up and restoring the database

Everything that is not a key or a configuration value lives in Postgres: credentials, approvals, the ledger and its timestamp
tokens, users, sessions, two-factor enrolments and the audit log. Losing the volume loses all of it, so back it up.

```bash
export BACKUP_PASSPHRASE='a long passphrase you will not lose'   # at least 12 characters; strongly recommended
KEEP=14 scripts/backup.sh          # writes backups/acvs-<UTC time>.dump.enc and a .sha256 file, keeps the newest 14
```

The backup is a consistent snapshot taken while the system runs. It is encrypted when `BACKUP_PASSPHRASE` is set (it holds
password hashes and the sealed signing keys), readable only by you, read back and counted before it is kept, and
checksummed. It does **not** contain `ENCRYPTION_KEY`: keep that (and your `key-backup`) elsewhere. A backup without the key
restores credentials and history, but the signing keys in it cannot be opened. Copy the files off the host; a backup on the
same disk is not a backup. For the production stack set `COMPOSE_FILE=docker-compose.prod.yml`. To run it nightly:
`17 2 * * * cd /srv/acvs && BACKUP_PASSPHRASE=... KEEP=30 scripts/backup.sh`.

To restore after losing the database (or to move to a new host):

```bash
# new host: copy .env with the SAME ENCRYPTION_KEY, then start only the database
docker compose up -d postgres
BACKUP_PASSPHRASE=... scripts/restore.sh backups/acvs-20261101T021700Z.dump.enc   # add --yes if the database holds data
docker compose up -d
```

`restore.sh` checks the checksum, decrypts and reads the whole backup *before* it touches anything, so a damaged file or a
wrong passphrase costs you nothing. It then replaces the database, starts the backend (which applies newer migrations and
refuses to run if `ENCRYPTION_KEY` is wrong) and verifies the restored ledger. Changes made after the backup are gone, so
the audit log and the ledger return to that moment. Test a restore on a spare machine now and then.
`scripts/backup-test.sh` does exactly this in CI: it destroys the volume, restores, and checks credentials, a revocation, a
user's two-factor, the signing keys and the ledger.

**Withdrawing a release.** Migrations only go forward when the server starts. If a release has to be undone, run
`scripts/migrate-down.sh TARGET --yes` (for example `6` undoes migrations 0008 and 0007). Each undo script in
`backend/migrations-down/` says what data it deletes; a backup is taken first, the backend is stopped, and you then start the
older release. Migration 0001 cannot be undone (that would be the whole database): restore a backup instead. The test applies
and reverses every migration and checks the schema is identical afterwards.

## Health checks, logs and metrics

| Endpoint | Where | Meaning |
|----------|-------|---------|
| `/health` | backend port 8000 (not published) | the process is alive; never touches the database |
| `/ready` | backend port 8000 (not published) | the database answers `SELECT 1` within 2 seconds, otherwise `503`. Compose uses it as the health check, and a load balancer should too |
| `/metrics` | `METRICS_BIND` (default `0.0.0.0:9090` inside the compose network, **not published**) | Prometheus text format; empty `METRICS_BIND` turns it off |

The metrics port is a separate listener so the public web server and the reverse proxy can never reach it. Point Prometheus at
`backend:9090` from inside the network; do not publish the port. Exported: request counts and a latency histogram per route
template (`/api/v1/credentials/:id`, never the real id), audit events by action (`LOGIN_FAILED`, `CREDENTIAL_SIGNED`, `BLOCK_SEALED`, ...),
rate-limit refusals by kind of limit, credentials by status, ledger height, seconds since the last block, issued credentials still
waiting to be sealed, blocks without an outside timestamp, active sessions, database pool use and whether the database answered the scrape.
No label holds an e-mail address, a client address or an identifier. Suggested alerts:

```yaml
- alert: AcvsDatabaseDown          # the backend cannot reach Postgres
  expr: acvs_db_up == 0
  for: 2m
- alert: AcvsLoginFailuresSpike    # someone is guessing passwords
  expr: sum(rate(acvs_audit_events_total{action=~"LOGIN_FAILED|LOGIN_MFA_FAILED"}[5m])) > 1
  for: 10m
- alert: AcvsNotSealing            # approved credentials are not being anchored in the ledger
  expr: acvs_credentials_waiting_for_seal > 0 and acvs_ledger_last_block_age_seconds > 86400
- alert: AcvsNoOutsideTimestamp    # only if you configured a timestamp authority
  expr: acvs_blocks_without_external_timestamp > 3
  for: 1h
- alert: AcvsServerErrors
  expr: sum(rate(acvs_http_requests_total{status=~"5.."}[5m])) > 0.1
  for: 10m
```

Logs go to standard output. `LOG_FORMAT=json` writes one JSON object per line for a log shipper (default is plain text). Every
request gets an `X-Request-Id` (a plain id sent by the proxy is kept, anything else is replaced), which appears in the response and
on that request's log lines, so a user's failing request can be found. Logs name the route template, never the path, query string,
password or token. Health checks are logged only at debug level. `RUST_LOG` sets the level.
`scripts/observability-test.sh` checks all of this on a running stack, including what happens when the database stops.

## Security controls

| Control | Implementation |
|---|---|
| RBAC | Role read from the database on every request (demotion/deactivation is immediate); per-endpoint checks |
| Auth | Argon2id passwords with a common-password check, HS256 JWT bound to a server-side session (logout revokes; sessions are listable and revocable), 8h expiry, timing-equalised login, optional or required TOTP second factor |
| Replay protection | Every POST needs `X-Nonce` (single use) and `X-Timestamp` (within 60s) |
| Rate limiting | Counted in Postgres, so it holds across instances and restarts: 10 logins/min and 240 anonymous requests/min per client address, 600 requests/min per signed-in user, and failed logins throttled per account (20 per 15 min) whatever the address; configurable |
| Input / WAF | Field validation, 16 KB body limit, security headers + strict CSP, parameterised SQL only; production stack adds the OWASP Core Rule Set WAF |
| Container | Backend runs as an unprivileged user (uid 10001) on a read-only filesystem with all capabilities dropped and `no-new-privileges` |
| Transport | Production stack: automatic HTTPS (TLS 1.2/1.3), HTTP to HTTPS redirect, HSTS; only ports 80/443 exposed |
| Secrets | `.env` generated locally and git-ignored; CI generates throwaway secrets |
| CI/CD | GitHub Actions: fmt, clippy `-D warnings`, unit tests, front end build, full-stack smoke test |

## API

Public: `POST /auth/login`, `POST /auth/login/mfa`, `POST /auth/reset-password`, `GET /verify/:id`, `GET /credentials/:id/qr`, `GET /ledger/verify`.
Authenticated: `GET /auth/me`, `POST /auth/logout`, `GET|POST /credentials`, `GET /credentials/:id`,
`POST /credentials/:id/{approve,reject,revoke,reissue}`, `GET /keys`, `POST /keys/:role/rotate`, `POST /keys/:id/revoke`,
`GET /ledger/blocks`, `POST /ledger/seal`, `GET /audit`, `POST /auth/password`, `GET /auth/sessions`,
`POST /auth/sessions/:id/revoke`, `POST /auth/sessions/revoke-others`, `GET /auth/totp`,
`POST /auth/totp/{setup,enable,disable,recovery-codes}`.
`university_admin` only: `GET|POST /users`, `POST /users/:id/{role,active,password,reset-link,totp/reset,sessions/revoke}`. All under `/api/v1`.

## Limits you should know about

- **The ledger is not a public blockchain.** It is a signed, hash-linked Merkle ledger in your own database. On its own it detects tampering, but whoever controls the DB *and* the university key could rewrite history. Configure an external timestamp authority (see above) so that rewriting history would contradict a signature you do not control; without one this limit applies in full.
- Rate limits are fixed windows, so a client can burst up to twice a limit across a window boundary. The per-account login throttle can be used to lock a victim out for the rest of its window by someone who keeps guessing their email; it throttles, it does not disable the account.
- The built-in WAF is the generic OWASP rule set on a single host. It does not absorb DDoS traffic or replace a managed WAF/CDN; for large-scale exposure put one in front of the edge.
- The encryption key lives in an environment variable and can be rotated (above), but it is still a plain secret on the host. For higher assurance wrap the signing keys with a KMS/HSM (for example HashiCorp Vault's Transit engine); that is not built in. Losing it is recoverable only if you made a key backup (see above).
- Stage keys belong to a stage, not a person; for personal accountability use personal signatures (above), which are optional unless `REQUIRE_PERSONAL_SIGNATURES=true`.
- Password reset is administrator-assisted (no e-mail), and two-factor sign-in is opt-in unless `REQUIRE_MFA_ROLES` is set. Authenticator codes can be phished like passwords; the optional personal security keys (above) are the phishing-resistant option for approvals.

## Tests

`scripts/test.sh` runs the fast tests in about a minute (it starts a throwaway Postgres in Docker for the API tests):

| Layer | What | Where |
|-------|------|-------|
| Rust unit tests | cryptography, Merkle proofs, stage order, verdict rules, password and TOTP rules, address handling | `backend/src/*.rs` (`mod tests`) |
| Rust API tests | the real router against a real database, one fresh database per test: the four-stage lifecycle, who may do what, rejection, revocation and re-issue, tampering detected, append-only triggers, the ledger, key rotation, sign-in, lock-out, password change and reset links, replayed requests, audit records | `backend/src/api_tests.rs` |
| Front-end tests | Vitest + Testing Library: request signing headers, session handling, navigation per role, the two-step sign-in, password reset, the public verification page | `frontend/src/*.test.ts(x)` |

The API tests need `DATABASE_URL` to point at a Postgres server you may create databases on, for example
`docker run -d -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:16-alpine` and
`DATABASE_URL=postgres://postgres:test@localhost:55432/postgres cargo test` in `backend/`.

The scripts in `scripts/` (`smoke.sh`, `auth-test.sh`, `prod-test.sh`, `rotation-test.sh`, ...) and `e2e/` test whole running stacks, including TLS, the WAF, Docker and a real browser. CI runs all of them.

## Dependency, secret and image scanning

`scripts/audit.sh` runs the checks CI runs on every push and pull request and again every Monday (new advisories appear without any code change):

- **Rust crates:** `cargo audit --deny warnings` against the RustSec database. Advisories that were reviewed and accepted are listed with their reasons in `backend/.cargo/audit.toml`.
- **npm packages:** `npm audit --audit-level=high` (the production dependencies, which are only React, have none).
- **Secrets:** gitleaks over the files and the whole git history, with the throw-away passwords in two test scripts allowed in `.gitleaks.toml`.
- **Images:** Trivy on the backend and front-end images; any fixable high or critical vulnerability, or a secret inside an image, fails the build. The images other projects publish (Postgres, the WAF, Caddy) are scanned and reported but do not fail it, because we cannot patch them.
- **Updates:** `.github/dependabot.yml` opens weekly pull requests for Cargo, npm, both Dockerfiles, the images named in the compose files and the GitHub Actions.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
