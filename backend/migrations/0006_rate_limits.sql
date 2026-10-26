-- Rate-limit counters shared by every backend instance (fixed windows). Rows are tiny and expire on their own:
-- the backend deletes the ones whose window ended long ago.
CREATE TABLE rate_limits (
    key          text PRIMARY KEY,
    -- start of the current fixed window, in unix seconds (aligned to the window length)
    window_start bigint NOT NULL,
    hits         integer NOT NULL
);
CREATE INDEX rate_limits_window_idx ON rate_limits(window_start);
