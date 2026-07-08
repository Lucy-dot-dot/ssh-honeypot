-- Migration 013: reported_ips table + LISTEN/NOTIFY trigger.
--
-- Lets the operator flag attacker IPs as "reported" directly from the
-- dashboard GUI. Each row holds the IP, the timestamp it was flagged, and
-- free-form notes the operator typed at report time. The dashboard shows a
-- marker in front of every reported IP across all feeds and keeps the list
-- live via NOTIFY (the same mechanism used by auth/conn/session feeds).

CREATE TABLE reported_ips (
    ip INET PRIMARY KEY,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_reported_ips_reported_at ON reported_ips(reported_at);

COMMENT ON TABLE reported_ips IS 'IPs the operator flagged as "reported" from the dashboard';
COMMENT ON COLUMN reported_ips.notes IS 'Free-form notes typed when the report was added';

-- NOTIFY: any change to reported_ips (add / edit notes / remove) pings the
-- dashboard so the markers and the manager window update in near-real-time.
-- Mirrors the trigger pattern from migration 012.
CREATE OR REPLACE FUNCTION notify_reported_ip_change() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('reported_ip_change', '');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_reported_ips_change_notify ON reported_ips;
CREATE TRIGGER trg_reported_ips_change_notify
    AFTER INSERT OR UPDATE OR DELETE ON reported_ips
    FOR EACH ROW EXECUTE FUNCTION notify_reported_ip_change();
