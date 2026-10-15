CREATE TABLE users (
    id            uuid PRIMARY KEY,
    email         text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('faculty','exam_cell','registrar','university_admin','auditor')),
    active        boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE signing_keys (
    id              uuid PRIMARY KEY,
    role            text NOT NULL CHECK (role IN ('faculty','exam_cell','registrar','university')),
    public_key      text NOT NULL UNIQUE,
    private_key_enc bytea NOT NULL,
    status          text NOT NULL CHECK (status IN ('active','retired','revoked')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    revoke_reason   text
);
CREATE UNIQUE INDEX one_active_key_per_role ON signing_keys(role) WHERE status = 'active';

CREATE TABLE blocks (
    height      bigint PRIMARY KEY,
    prev_hash   text NOT NULL,
    merkle_root text NOT NULL,
    leaves      jsonb NOT NULL,
    ts          bigint NOT NULL,
    block_hash  text NOT NULL UNIQUE,
    signature   text NOT NULL,
    key_id      uuid NOT NULL REFERENCES signing_keys(id)
);

CREATE TABLE credentials (
    id              uuid PRIMARY KEY,
    student_id      text NOT NULL,
    student_name    text NOT NULL,
    program         text NOT NULL,
    graduation_date date NOT NULL,
    gpa             text,
    honors          text,
    credential_hash text NOT NULL UNIQUE,
    status          text NOT NULL CHECK (status IN
        ('pending_exam_cell','pending_registrar','pending_university','issued','rejected','revoked')),
    created_by      uuid NOT NULL REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    revoke_reason   text,
    block_height    bigint REFERENCES blocks(height),
    leaf_index      int
);
CREATE INDEX credentials_status_idx ON credentials(status);
CREATE INDEX credentials_created_by_idx ON credentials(created_by);

CREATE TABLE approvals (
    id            uuid PRIMARY KEY,
    credential_id uuid NOT NULL REFERENCES credentials(id),
    role          text NOT NULL CHECK (role IN ('faculty','exam_cell','registrar','university')),
    approver_id   uuid NOT NULL REFERENCES users(id),
    key_id        uuid NOT NULL REFERENCES signing_keys(id),
    signature     text NOT NULL,
    signed_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (credential_id, role)
);

CREATE TABLE nonces (
    nonce   text PRIMARY KEY,
    used_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX nonces_used_at_idx ON nonces(used_at);

CREATE TABLE audit_logs (
    id            bigserial PRIMARY KEY,
    action        text NOT NULL,
    actor_id      uuid,
    actor_email   text,
    resource_type text,
    resource_id   text,
    details       jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION forbid_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER approvals_append_only   BEFORE UPDATE OR DELETE ON approvals   FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER blocks_append_only      BEFORE UPDATE OR DELETE ON blocks      FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER audit_logs_append_only  BEFORE UPDATE OR DELETE ON audit_logs  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
