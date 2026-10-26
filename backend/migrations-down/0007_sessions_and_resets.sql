-- Undoes 0007. Loses pending password-reset links and the address/device recorded on sessions.
DROP TABLE password_resets;
DROP INDEX sessions_user_idx;
ALTER TABLE sessions DROP COLUMN user_agent;
ALTER TABLE sessions DROP COLUMN ip;
