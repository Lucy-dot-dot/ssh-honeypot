-- Create useful PostgreSQL extensions for the SSH honeypot
-- This file is executed automatically when the PostgreSQL container starts

-- Note: We use gen_random_uuid() which is built into PostgreSQL 13+
-- so no uuid-ossp extension needed

-- Enable CIDR/INET operators for IP address analysis
-- (Built into PostgreSQL core, but good to be explicit)

-- Optional: Enable additional extensions for future analytics
-- CREATE EXTENSION IF NOT EXISTS "pg_stat_statements"; -- Query performance analytics
-- CREATE EXTENSION IF NOT EXISTS "pgcrypto";           -- Additional crypto functions