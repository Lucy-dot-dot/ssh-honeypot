//! Dashboard data layer: queries for the live-activity dashboard GUI.
//!
//! All IP values are returned via the SQL `host(ip)` function so they appear
//! without a CIDR suffix (e.g. `1.2.3.4` rather than `1.2.3.4/32`).
//!
//! Queries use runtime `sqlx::query_as` (not the compile-time-checked macros)
//! so the dashboard GUI can be built without a live `DATABASE_URL`.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Row};

/// A recent connection-tracking row (conn_track table).
#[derive(Debug, Clone, FromRow)]
pub struct RecentConnRow {
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub port: Option<i32>,
    pub local_port: Option<i32>,
}

/// A recent authentication attempt (auth table).
#[derive(Debug, Clone, FromRow)]
pub struct RecentAuthRow {
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub username: String,
    pub password: Option<String>,
    pub auth_type: Option<String>,
    pub successful: Option<bool>,
}

/// A currently-open session (sessions.end_time IS NULL).
#[derive(Debug, Clone, FromRow)]
pub struct LiveSessionRow {
    pub session_id: String,
    pub auth_id: String,
    pub ip: String,
    pub username: String,
    pub auth_type: Option<String>,
    pub successful: Option<bool>,
    pub start_time: DateTime<Utc>,
}

/// A recently-ended session (sessions.end_time IS NOT NULL).
#[derive(Debug, Clone, FromRow)]
pub struct EndedSessionRow {
    pub session_id: String,
    pub auth_id: String,
    pub ip: String,
    pub username: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_seconds: Option<i64>,
    pub command_count: i64,
}

/// A single command row for session detail views.
#[derive(Debug, Clone, FromRow)]
pub struct CommandRow {
    pub timestamp: DateTime<Utc>,
    pub command: String,
}

/// A single uploaded-file row for session detail views.
#[derive(Debug, Clone, FromRow)]
pub struct FileRow {
    pub timestamp: DateTime<Utc>,
    pub filename: String,
    pub file_size: i64,
    pub file_hash: Option<String>,
    pub claimed_mime_type: Option<String>,
    pub detected_mime_type: Option<String>,
    pub format_mismatch: Option<bool>,
    pub file_entropy: Option<f64>,
}

/// Full detail for one auth/session: auth fields + commands + files.
#[derive(Debug, Clone)]
pub struct SessionDetail {
    pub auth_id: String,
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub username: String,
    pub auth_type: Option<String>,
    pub password: Option<String>,
    pub successful: Option<bool>,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub city: Option<String>,
    pub commands: Vec<CommandRow>,
    pub files: Vec<FileRow>,
}

/// A `(value, count)` pair used in the "Top IPs / passwords / usernames" lists.
#[derive(Debug, Clone, FromRow)]
pub struct TopEntry {
    pub value: String,
    pub count: i64,
}

/// A point-in-time snapshot of dashboard activity.
#[derive(Debug, Clone, Default)]
pub struct DashboardSnapshot {
    pub fetched_at: Option<DateTime<Utc>>,
    pub recent_connections: Vec<RecentConnRow>,
    pub recent_auths: Vec<RecentAuthRow>,
    pub live_sessions: Vec<LiveSessionRow>,
    pub recent_sessions: Vec<EndedSessionRow>,
    pub top_ips: Vec<TopEntry>,
    pub top_passwords: Vec<TopEntry>,
    pub top_usernames: Vec<TopEntry>,
}

/// Dashboard query helper. Holds a cloneable connection pool.
#[derive(Clone)]
pub struct Dashboard {
    pool: PgPool,
}

impl Dashboard {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Fetch every dashboard section in one shot.
    pub async fn snapshot(&self) -> Result<DashboardSnapshot, sqlx::Error> {
        let mut snap = DashboardSnapshot::default();
        snap.fetched_at = Some(Utc::now());
        snap.recent_connections = self.recent_connections(20).await?;
        snap.recent_auths = self.recent_auths(40).await?;
        snap.live_sessions = self.live_sessions().await?;
        snap.recent_sessions = self.recent_sessions(20).await?;
        snap.top_ips = self.top_ips(15).await?;
        snap.top_passwords = self.top_passwords(15).await?;
        snap.top_usernames = self.top_usernames(15).await?;
        Ok(snap)
    }

    /// Most recent connection-tracking events.
    pub async fn recent_connections(&self, limit: i64) -> Result<Vec<RecentConnRow>, sqlx::Error> {
        sqlx::query_as::<_, RecentConnRow>(
            r#"
            SELECT timestamp, host(ip) AS ip, port, local_port
            FROM conn_track
            ORDER BY timestamp DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Most recent authentication attempts.
    pub async fn recent_auths(&self, limit: i64) -> Result<Vec<RecentAuthRow>, sqlx::Error> {
        sqlx::query_as::<_, RecentAuthRow>(
            r#"
            SELECT timestamp, host(ip) AS ip, username, password, auth_type, successful
            FROM auth
            ORDER BY timestamp DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// All currently-open sessions (end_time IS NULL), joined to auth for context.
    pub async fn live_sessions(&self) -> Result<Vec<LiveSessionRow>, sqlx::Error> {
        sqlx::query_as::<_, LiveSessionRow>(
            r#"
            SELECT
                s.id::text         AS session_id,
                s.auth_id::text    AS auth_id,
                host(a.ip)         AS ip,
                a.username         AS username,
                a.auth_type        AS auth_type,
                a.successful       AS successful,
                s.start_time       AS start_time
            FROM sessions s
            JOIN auth a ON a.id = s.auth_id
            WHERE s.end_time IS NULL
            ORDER BY s.start_time DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
    }

    /// Most recently-ended sessions with a command count.
    pub async fn recent_sessions(
        &self,
        limit: i64,
    ) -> Result<Vec<EndedSessionRow>, sqlx::Error> {
        sqlx::query_as::<_, EndedSessionRow>(
            r#"
            SELECT
                s.id::text          AS session_id,
                s.auth_id::text     AS auth_id,
                host(a.ip)          AS ip,
                a.username          AS username,
                s.start_time        AS start_time,
                s.end_time          AS end_time,
                s.duration_seconds  AS duration_seconds,
                COALESCE((
                    SELECT COUNT(*) FROM commands c WHERE c.auth_id = s.auth_id
                ), 0)               AS command_count
            FROM sessions s
            JOIN auth a ON a.id = s.auth_id
            WHERE s.end_time IS NOT NULL
            ORDER BY s.end_time DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Top source IPs by auth-attempt count.
    pub async fn top_ips(&self, limit: i64) -> Result<Vec<TopEntry>, sqlx::Error> {
        sqlx::query_as::<_, TopEntry>(
            r#"
            SELECT host(ip) AS value, COUNT(*)::int8 AS count
            FROM auth
            GROUP BY ip
            ORDER BY count DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Top passwords by auth-attempt count (non-empty only).
    pub async fn top_passwords(&self, limit: i64) -> Result<Vec<TopEntry>, sqlx::Error> {
        sqlx::query_as::<_, TopEntry>(
            r#"
            SELECT password AS value, COUNT(*)::int8 AS count
            FROM auth
            WHERE password IS NOT NULL AND password <> ''
            GROUP BY password
            ORDER BY count DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Top usernames by auth-attempt count.
    pub async fn top_usernames(&self, limit: i64) -> Result<Vec<TopEntry>, sqlx::Error> {
        sqlx::query_as::<_, TopEntry>(
            r#"
            SELECT username AS value, COUNT(*)::int8 AS count
            FROM auth
            GROUP BY username
            ORDER BY count DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Full detail for one auth id: enriched auth fields + commands + uploaded files.
    pub async fn session_detail(&self, auth_id: &str) -> Result<SessionDetail, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT
                a.id::text          AS auth_id,
                a.timestamp         AS timestamp,
                host(a.ip)          AS ip,
                a.username          AS username,
                a.auth_type         AS auth_type,
                a.password          AS password,
                a.successful        AS successful,
                COALESCE(ab.country_code, ip.country_code) AS country_code,
                ip.isp              AS isp,
                ip.city             AS city
            FROM auth a
            LEFT JOIN abuse_ip_cache ab ON ab.ip = a.ip
            LEFT JOIN ipapi_cache ip ON ip.ip = a.ip
            WHERE a.id = $1::uuid
            "#,
        )
        .bind(auth_id)
        .fetch_optional(&self.pool)
        .await?;

        let row = match row {
            Some(r) => r,
            None => return Err(sqlx::Error::RowNotFound),
        };

        let commands = sqlx::query_as::<_, CommandRow>(
            r#"
            SELECT timestamp, command
            FROM commands
            WHERE auth_id = $1::uuid
            ORDER BY timestamp ASC
            "#,
        )
        .bind(auth_id)
        .fetch_all(&self.pool)
        .await?;

        let files = sqlx::query_as::<_, FileRow>(
            r#"
            SELECT
                timestamp,
                filename,
                file_size,
                file_hash,
                claimed_mime_type,
                detected_mime_type,
                format_mismatch,
                file_entropy
            FROM uploaded_files
            WHERE auth_id = $1::uuid
            ORDER BY timestamp ASC
            "#,
        )
        .bind(auth_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(SessionDetail {
            auth_id: row.get("auth_id"),
            timestamp: row.get("timestamp"),
            ip: row.get("ip"),
            username: row.get("username"),
            auth_type: row.get("auth_type"),
            password: row.get("password"),
            successful: row.get("successful"),
            country_code: row.get("country_code"),
            isp: row.get("isp"),
            city: row.get("city"),
            commands,
            files,
        })
    }
}
