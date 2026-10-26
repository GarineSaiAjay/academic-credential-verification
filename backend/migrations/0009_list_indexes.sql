-- Lists page through credentials newest first and filter by student: both need an index to stay fast.
CREATE INDEX credentials_created_idx ON credentials (created_at DESC, id DESC);
CREATE INDEX credentials_student_idx ON credentials (student_id);
CREATE INDEX audit_logs_action_idx ON audit_logs (action, id DESC);
