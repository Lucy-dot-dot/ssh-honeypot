-- SSH Honeypot PostgreSQL Schema
-- Migration 001: Initial schema creation

-- Authentication attempts table
CREATE TABLE auth (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip INET NOT NULL,
    username VARCHAR(255) NOT NULL,
    auth_type VARCHAR(50) NOT NULL,
    password TEXT,
    public_key TEXT,
    successful BOOLEAN NOT NULL DEFAULT FALSE
);

-- Commands table with foreign key to auth
CREATE TABLE commands (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    auth_id UUID NOT NULL REFERENCES auth(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    command TEXT NOT NULL
);

-- Sessions table with foreign key to auth
CREATE TABLE sessions (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    auth_id UUID NOT NULL REFERENCES auth(id) ON DELETE CASCADE,
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ NOT NULL,
    duration_seconds BIGINT NOT NULL
);

-- Uploaded files table with foreign key to auth
CREATE TABLE uploaded_files (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    auth_id UUID NOT NULL REFERENCES auth(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    filename VARCHAR(255) NOT NULL,
    filepath TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    claimed_mime_type VARCHAR(100),
    detected_mime_type VARCHAR(100),
    format_mismatch BOOLEAN NOT NULL DEFAULT FALSE,
    file_entropy DOUBLE PRECISION,
    binary_data BYTEA NOT NULL
);

-- AbuseIPDB cache table with automatic expiration
CREATE TABLE abuse_ip_cache (
    ip INET PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    abuse_confidence_score SMALLINT,
    country_code VARCHAR(2),
    is_tor BOOLEAN NOT NULL DEFAULT FALSE,
    is_whitelisted BOOLEAN,
    total_reports INTEGER NOT NULL DEFAULT 0,
    response_data JSONB NOT NULL
);

-- Indexes for performance
CREATE INDEX idx_auth_timestamp ON auth(timestamp);
CREATE INDEX idx_auth_ip ON auth(ip);
CREATE INDEX idx_auth_successful ON auth(successful);

CREATE INDEX idx_commands_auth_id ON commands(auth_id);
CREATE INDEX idx_commands_timestamp ON commands(timestamp);

CREATE INDEX idx_sessions_auth_id ON sessions(auth_id);
CREATE INDEX idx_sessions_start_time ON sessions(start_time);

CREATE INDEX idx_uploaded_files_auth_id ON uploaded_files(auth_id);
CREATE INDEX idx_uploaded_files_timestamp ON uploaded_files(timestamp);
CREATE INDEX idx_uploaded_files_hash ON uploaded_files(file_hash);

CREATE INDEX idx_abuse_ip_cache_timestamp ON abuse_ip_cache(timestamp);

-- Comments for documentation
COMMENT ON TABLE auth IS 'SSH authentication attempts - all login attempts are logged';
COMMENT ON TABLE commands IS 'Commands executed in SSH sessions';
COMMENT ON TABLE sessions IS 'SSH session metadata with start/end times';
COMMENT ON TABLE uploaded_files IS 'Files uploaded via SFTP with threat analysis';
COMMENT ON TABLE abuse_ip_cache IS 'Cached AbuseIPDB IP intelligence data';

COMMENT ON COLUMN auth.ip IS 'Client IP address as INET type for efficient storage and queries';
COMMENT ON COLUMN uploaded_files.file_entropy IS 'Shannon entropy for detecting packed/encrypted files';
COMMENT ON COLUMN abuse_ip_cache.response_data IS 'Full AbuseIPDB response as JSONB for rich queries';