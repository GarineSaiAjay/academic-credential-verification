-- A rejection or revocation is a signed, append-only event instead of just a mutable status column.
-- The signature binds the event to the credential's content hash, the stage key that issued it, the
-- reason and the time, so verification can tell a real revocation from an edited status.
CREATE TABLE credential_events (
    credential_id uuid PRIMARY KEY REFERENCES credentials(id),
    kind          text NOT NULL CHECK (kind IN ('rejected','revoked')),
    stage         text NOT NULL CHECK (stage IN ('faculty','exam_cell','registrar','university')),
    reason        text NOT NULL,
    actor_id      uuid REFERENCES users(id),
    key_id        uuid NOT NULL REFERENCES signing_keys(id),
    signature     text NOT NULL,
    ts            bigint NOT NULL,
    -- true when the server signed it later for a status recorded before events existed
    legacy        boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER credential_events_append_only BEFORE UPDATE OR DELETE ON credential_events FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Once rejected or revoked, a credential's status can never change again (so it cannot be "un-revoked" by SQL).
CREATE FUNCTION forbid_final_status_change() RETURNS trigger AS $$
BEGIN
    IF OLD.status IN ('rejected','revoked') AND (
        NEW.status IS DISTINCT FROM OLD.status
        OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
        OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason
    ) THEN
        RAISE EXCEPTION 'credential % is % and its status is final', OLD.id, OLD.status;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credentials_final_status BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION forbid_final_status_change();
