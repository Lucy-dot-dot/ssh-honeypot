-- Replica-local event triggers for the logical replica (docker-compose.replica.yml).
--
-- Logical replication apply workers run with session_replication_role = 'replica',
-- so ordinary triggers do NOT fire for replicated rows. These copies of the
-- primary's NOTIFY triggers are marked ENABLE REPLICA, which makes the apply
-- worker fire them for every replicated row change. LISTEN on the replica:
--
--   auth_new          - one NOTIFY per new auth row
--   conn_new          - one NOTIFY per new conn_track row
--   session_change    - INSERT or UPDATE on sessions
--   reported_ip_change- INSERT/UPDATE/DELETE on reported_ips
--
-- The channel/payload definitions come from the primary's trigger functions
-- (notify_auth_new() etc.), which exist on the replica via the schema dump.
--
-- Idempotent: CREATE OR REPLACE TRIGGER + ALTER TABLE ... ENABLE REPLICA TRIGGER.
-- Applied automatically on every container start by the `trigger-ensure`
-- sidecar; safe to re-run manually with:
--   docker exec -i ssh-honeypot-replica-db psql -U honeypot -d ssh_honeypot \
--     < replica-triggers.sql

BEGIN;

CREATE OR REPLACE TRIGGER trg_auth_insert_notify
    AFTER INSERT ON public.auth
    FOR EACH ROW EXECUTE FUNCTION public.notify_auth_new();
ALTER TABLE public.auth ENABLE REPLICA TRIGGER trg_auth_insert_notify;

CREATE OR REPLACE TRIGGER trg_conn_track_insert_notify
    AFTER INSERT ON public.conn_track
    FOR EACH ROW EXECUTE FUNCTION public.notify_conn_new();
ALTER TABLE public.conn_track ENABLE REPLICA TRIGGER trg_conn_track_insert_notify;

CREATE OR REPLACE TRIGGER trg_sessions_change_notify
    AFTER INSERT OR UPDATE ON public.sessions
    FOR EACH ROW EXECUTE FUNCTION public.notify_session_change();
ALTER TABLE public.sessions ENABLE REPLICA TRIGGER trg_sessions_change_notify;

CREATE OR REPLACE TRIGGER trg_reported_ips_change_notify
    AFTER INSERT OR DELETE OR UPDATE ON public.reported_ips
    FOR EACH ROW EXECUTE FUNCTION public.notify_reported_ip_change();
ALTER TABLE public.reported_ips ENABLE REPLICA TRIGGER trg_reported_ips_change_notify;

COMMIT;
