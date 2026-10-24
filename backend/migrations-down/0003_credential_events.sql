-- Undoes 0003. Loses the signed rejection/revocation events; an older server then trusts the status column alone.
DROP TRIGGER credentials_final_status ON credentials;
DROP FUNCTION forbid_final_status_change();
DROP TABLE credential_events;
