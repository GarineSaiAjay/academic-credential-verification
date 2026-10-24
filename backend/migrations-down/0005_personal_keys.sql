-- Undoes 0005. Loses every registered personal key and every personal countersignature.
DROP TABLE approval_countersigs;
DROP TABLE webauthn_challenges;
DROP TABLE user_keys;
DROP FUNCTION forbid_key_material_change();
ALTER TABLE users DROP COLUMN key_enroll_until;
