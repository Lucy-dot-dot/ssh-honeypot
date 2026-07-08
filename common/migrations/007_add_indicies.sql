DROP INDEX idx_auth_ip;
CREATE INDEX idx_auth_ip_timestamp ON auth (ip, timestamp DESC);
CREATE INDEX idx_auth_password ON auth (password);