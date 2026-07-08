CREATE TABLE conn_track (
      id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
      timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ip INET NOT NULL
);

COMMENT ON TABLE conn_track IS 'Records all connection attempts';

CREATE INDEX idx_conn_track_ip ON conn_track(ip);
CREATE INDEX idx_conn_track_timestamp ON conn_track(timestamp);
