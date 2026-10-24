-- Sessions remember where they came from so people can recognise them in a list and revoke the ones they do not.
ALTER TABLE sessions ADD COLUMN ip text;
ALTER TABLE sessions ADD COLUMN user_agent text;
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- One-time password-reset links issued by an administrator. Only a hash of the token is stored.
CREATE TABLE password_resets (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id),
    token_hash bytea NOT NULL UNIQUE,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX password_resets_user_idx ON password_resets (user_id);
