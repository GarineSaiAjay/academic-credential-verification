-- RFC 3161 timestamp tokens that an external time-stamping authority signed over a block's hash.
-- A block without a row here is simply not timestamped yet. Rows are immutable once written.
CREATE TABLE block_timestamps (
    block_height bigint PRIMARY KEY REFERENCES blocks(height),
    imprint      text NOT NULL,
    tsa_url      text NOT NULL,
    request      bytea NOT NULL,
    response     bytea NOT NULL,
    gen_time     timestamptz NOT NULL,
    serial       text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER block_timestamps_append_only BEFORE UPDATE OR DELETE ON block_timestamps FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
