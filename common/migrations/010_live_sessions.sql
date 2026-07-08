-- Allow live (in-progress) sessions to be recorded.
--
-- Sessions are now inserted when a channel opens (with a NULL end_time) and
-- updated with the end_time + duration when the channel closes. This lets the
-- dashboard show currently active sessions (end_time IS NULL).
ALTER TABLE sessions ALTER COLUMN end_time DROP NOT NULL;
ALTER TABLE sessions ALTER COLUMN duration_seconds DROP NOT NULL;

-- Partial index that cheaply finds live sessions.
CREATE INDEX idx_sessions_end_time_null ON sessions(start_time)
    WHERE end_time IS NULL;

COMMENT ON COLUMN sessions.end_time IS 'NULL while the session is still active; set when the channel closes';
COMMENT ON COLUMN sessions.duration_seconds IS 'NULL while the session is still active; set when the channel closes';
