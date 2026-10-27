-- Migration 015: Link authentication attempts to their connection record.
--
-- Every connection is first recorded in conn_track; each authentication
-- attempt observed on that connection now references the corresponding
-- conn_track row. The column is nullable because rows recorded before this
-- migration predate the link. Deleting a conn_track row cascades to all
-- auth attempts (and their commands/sessions/uploads) made on it.

ALTER TABLE auth ADD COLUMN conn_id UUID REFERENCES conn_track(id) ON DELETE CASCADE;

CREATE INDEX idx_auth_conn_id ON auth (conn_id);

COMMENT ON COLUMN auth.conn_id IS 'conn_track row the attempt was observed on';
