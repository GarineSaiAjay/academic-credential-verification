-- Time-based one-time passwords (RFC 6238) as a second factor at sign-in.
CREATE TABLE user_totp (
    user_id      uuid PRIMARY KEY REFERENCES users(id),
    secret_enc   bytea NOT NULL,            -- sealed with the ENCRYPTION_KEY ring, like the signing keys
    confirmed_at timestamptz,               -- NULL while the person has not yet proved they can produce codes
    last_step    bigint NOT NULL DEFAULT 0, -- the newest 30-second step already used: a code works once
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Single-use recovery codes for a lost authenticator. Only hashes are stored.
CREATE TABLE totp_recovery (
    id        uuid PRIMARY KEY,
    user_id   uuid NOT NULL REFERENCES users(id),
    code_hash bytea NOT NULL,
    used_at   timestamptz,
    UNIQUE (user_id, code_hash)
);

-- A session opened by someone whose role requires a second factor they have not set up yet may do nothing
-- but set it up.
ALTER TABLE sessions ADD COLUMN mfa_pending boolean NOT NULL DEFAULT false;
