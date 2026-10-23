-- Personal signing keys: WebAuthn credentials (passkeys / security keys). The private key never leaves the
-- person's authenticator; the server stores only the public key and verifies signatures made with it.
CREATE TABLE user_keys (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users(id),
    credential_id bytea NOT NULL UNIQUE,
    -- P-256 public key, DER SubjectPublicKeyInfo
    public_key    bytea NOT NULL,
    label         text NOT NULL,
    -- retired: replaced or lost, past signatures stay valid. revoked: compromised, what it signed no longer verifies.
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired','revoked')),
    sign_count    bigint NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    ended_at      timestamptz,
    end_reason    text
);
CREATE INDEX user_keys_user_idx ON user_keys(user_id);

-- The key material of a registered key can never change; only its status and counter do.
CREATE FUNCTION forbid_key_material_change() RETURNS trigger AS $$
BEGIN
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.public_key IS DISTINCT FROM OLD.public_key
       OR NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION 'the key material of user key % cannot change', OLD.id;
    END IF;
    -- revoked is final; a retired key can still be revoked later, but never becomes active again
    IF (OLD.status = 'revoked' AND NEW.status IS DISTINCT FROM 'revoked')
       OR (OLD.status = 'retired' AND NEW.status = 'active') THEN
        RAISE EXCEPTION 'user key % is % and cannot become %', OLD.id, OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER user_keys_immutable BEFORE UPDATE ON user_keys FOR EACH ROW EXECUTE FUNCTION forbid_key_material_change();

-- An administrator can open a short window in which this user may enrol a key without an existing one (first
-- enrolment, or after losing every key). Without it, anyone who knew the password could add a key of their own.
ALTER TABLE users ADD COLUMN key_enroll_until timestamptz;

-- One-time challenges for registering a key.
CREATE TABLE webauthn_challenges (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id),
    challenge  bytea NOT NULL,
    expires_at timestamptz NOT NULL
);

-- A person's countersignature on an approval, kept exactly as their authenticator produced it so that anyone
-- can re-verify it: signature over authenticator_data || SHA-256(client_data_json).
CREATE TABLE approval_countersigs (
    approval_id        uuid PRIMARY KEY REFERENCES approvals(id),
    user_key_id        uuid NOT NULL REFERENCES user_keys(id),
    rp_id              text NOT NULL,
    origin             text NOT NULL,
    authenticator_data bytea NOT NULL,
    client_data_json   bytea NOT NULL,
    signature          bytea NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER approval_countersigs_append_only BEFORE UPDATE OR DELETE ON approval_countersigs FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
