-- A re-issued credential points at the one it replaces. The pointer is part of the content hash that the
-- faculty signature covers (hash version 2), so it cannot be edited without breaking verification.
ALTER TABLE credentials ADD COLUMN supersedes uuid REFERENCES credentials(id);
CREATE INDEX credentials_supersedes_idx ON credentials(supersedes) WHERE supersedes IS NOT NULL;
