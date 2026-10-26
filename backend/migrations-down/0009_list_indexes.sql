-- Undoes 0009. Only indexes: no data is lost, lists just get slower.
DROP INDEX audit_logs_action_idx;
DROP INDEX credentials_student_idx;
DROP INDEX credentials_created_idx;
