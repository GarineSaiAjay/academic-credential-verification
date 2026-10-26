-- Undoes 0008. Loses every two-factor enrolment and recovery code: people with it on sign in with a password only.
DROP TABLE totp_recovery;
DROP TABLE user_totp;
ALTER TABLE sessions DROP COLUMN mfa_pending;
