-- Migration 012: LISTEN/NOTIFY triggers for near-real-time dashboard updates.
--
-- Emits a notification on a dedicated channel whenever a row is inserted (or,
-- for sessions, inserted/updated) into the three "recent" feeds the dashboard
-- shows. The dashboard-gui binary LISTENs on these channels and refreshes the
-- affected feed within ~1s instead of polling on a fixed timer.
--
-- Payloads are intentionally empty: the dashboard re-runs its cheap indexed
-- ORDER BY timestamp DESC LIMIT N queries on every notification, so there is
-- no need to ship row data through the NOTIFY payload (capped at 8kB anyway).

-- auth: a new authentication attempt was recorded.
CREATE OR REPLACE FUNCTION notify_auth_new() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('auth_new', '');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auth_insert_notify ON auth;
CREATE TRIGGER trg_auth_insert_notify
    AFTER INSERT ON auth
    FOR EACH ROW EXECUTE FUNCTION notify_auth_new();

-- conn_track: a new connection was recorded.
CREATE OR REPLACE FUNCTION notify_conn_new() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('conn_new', '');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_conn_track_insert_notify ON conn_track;
CREATE TRIGGER trg_conn_track_insert_notify
    AFTER INSERT ON conn_track
    FOR EACH ROW EXECUTE FUNCTION notify_conn_new();

-- sessions: INSERT = a new live session started; UPDATE = end_time/duration
-- set (live -> ended). Both transitions are visible in the dashboard, so the
-- trigger fires on either operation.
CREATE OR REPLACE FUNCTION notify_session_change() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('session_change', '');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sessions_change_notify ON sessions;
CREATE TRIGGER trg_sessions_change_notify
    AFTER INSERT OR UPDATE ON sessions
    FOR EACH ROW EXECUTE FUNCTION notify_session_change();
