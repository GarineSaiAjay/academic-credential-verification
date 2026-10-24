-- Undoes 0004. Loses the link from a re-issued credential to the one it replaced; those credentials then
-- fail their integrity check on a server that does not know hash version 2.
DROP INDEX credentials_supersedes_idx;
ALTER TABLE credentials DROP COLUMN supersedes;
