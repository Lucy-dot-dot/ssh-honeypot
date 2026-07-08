-- Speeds up the dashboard "Top Usernames" aggregate.
--
-- Before this index, `SELECT username, COUNT(*) FROM auth GROUP BY username`
-- did a parallel sequential scan over the auth table. On a honeypot with
-- ~5 million auth rows that query alone took ~14 seconds, dominating the
-- dashboard refresh time. With the index PostgreSQL uses an index-only scan
-- (matching the existing idx_auth_password / idx_auth_ip_timestamp used by the
-- other top-N aggregates), bringing it down to ~2s.
CREATE INDEX IF NOT EXISTS idx_auth_username ON auth (username);
