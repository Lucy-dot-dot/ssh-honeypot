use std::path::PathBuf;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Result as SqlResult};
use tokio::sync::mpsc;

// Database message types
#[derive(Debug)]
pub enum DbMessage {
    RecordAuth {
        id: String,
        timestamp: DateTime<Utc>,
        ip: String,
        username: String,
        auth_type: String,
        password: Option<String>,
        public_key: Option<String>,
        successful: bool,
    },
    RecordCommand {
        id: String,
        auth_id: String,
        timestamp: DateTime<Utc>,
        command: String,
    },
    RecordSession {
        auth_id: String,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        duration_seconds: i64,
    },
    Shutdown,
}

// Database handler function that runs in its own task
pub async fn run_db_handler(mut rx: mpsc::Receiver<DbMessage>, db_path: PathBuf) {
    log::trace!("start db handler");
    log::debug!("Using path to db: {}", db_path.display());
    // Create database connection
    let conn = match initialize_database(&db_path) {
        Ok(conn) => {
            log::trace!("db connection successfully and initialized");
            conn
        },
        Err(e) => {
            log::error!("Failed to initialize database: {}", e);
            return;
        }
    };

    // Process database messages
    while let Some(msg) = rx.recv().await {
        log::trace!("handle msg: {:?}", msg);
        match msg {
            DbMessage::RecordAuth { id, timestamp, ip, username, auth_type, password, public_key, successful } => {
                if let Err(e) = record_auth(
                    &conn, id, timestamp, ip, username, auth_type,
                    password, public_key, successful
                ) {
                    log::error!("Database error recording auth: {}", e);
                }
            },
            DbMessage::RecordCommand { id, auth_id, timestamp, command } => {
                if let Err(e) = record_command(&conn, id, auth_id, timestamp, command) {
                    log::error!("Database error recording command: {}", e);
                }
            },
            DbMessage::RecordSession { auth_id, start_time, end_time, duration_seconds } => {
                if let Err(e) = record_session(&conn, auth_id, start_time, end_time, duration_seconds) {
                    log::error!("Database error recording session: {}", e);
                }
            },
            DbMessage::Shutdown => {
                break;
            }
        }
    }
    log::trace!("db handler stopped");
}

// Initialize the SQLite database
fn initialize_database(db_path: &PathBuf) -> SqlResult<Connection> {
    log::trace!("Opening db file");
    let conn = Connection::open(db_path)?;

    log::trace!("Adding auth table if not existing");
    // Create auth table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS auth (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            username TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            password TEXT,
            public_key TEXT,
            successful INTEGER NOT NULL
        )",
        [],
    )?;

    log::trace!("Adding commands table if not existing");
    // Create commands table with foreign key to auth
    conn.execute(
        "CREATE TABLE IF NOT EXISTS commands (
            id TEXT PRIMARY KEY,
            auth_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            command TEXT NOT NULL,
            FOREIGN KEY(auth_id) REFERENCES auth(id)
        )",
        [],
    )?;

    log::trace!("Adding sessions table if not existing");
    // Create sessions table with foreign key to auth
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions (
            auth_id TEXT PRIMARY KEY,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            duration_seconds INTEGER NOT NULL,
            FOREIGN KEY(auth_id) REFERENCES auth(id)
        )",
        [],
    )?;

    Ok(conn)
}

// Record authentication attempt in database
fn record_auth(
    conn: &Connection,
    id: String,
    timestamp: DateTime<Utc>,
    ip: String,
    username: String,
    auth_type: String,
    password: Option<String>,
    public_key: Option<String>,
    successful: bool,
) -> SqlResult<()> {
    let pass = password.unwrap_or(String::new());
    let key = public_key.unwrap_or(String::new());
    log::trace!("Recording into auth table: {}, {}, {}, {}, {}, {}, {}, {},", id, timestamp.to_rfc3339(), ip, username, auth_type, pass, key, successful);
    conn.execute(
        "INSERT INTO auth (id, timestamp, ip, username, auth_type, password, public_key, successful)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            timestamp.to_rfc3339(),
            ip,
            username,
            auth_type,
            pass,
            key,
            successful as i32,
        ],
    )?;

    Ok(())
}

// Record command in database
fn record_command(
    conn: &Connection,
    id: String,
    auth_id: String,
    timestamp: DateTime<Utc>,
    command: String,
) -> SqlResult<()> {
    log::trace!("Recording into command table: {}, {}, {}, {}",  id, timestamp.to_rfc3339(), command, timestamp);
    conn.execute(
        "INSERT INTO commands (id, auth_id, timestamp, command)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            id,
            auth_id,
            timestamp.to_rfc3339(),
            command,
        ],
    )?;

    Ok(())
}

// Record session in database
fn record_session(
    conn: &Connection,
    auth_id: String,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    duration_seconds: i64,
) -> SqlResult<()> {
    log::trace!("Recording into session table: {}, {}, {}, {}", auth_id, start_time.to_rfc3339(), end_time.to_rfc3339(), duration_seconds);
    conn.execute(
        "INSERT INTO sessions (auth_id, start_time, end_time, duration_seconds)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            auth_id,
            start_time.to_rfc3339(),
            end_time.to_rfc3339(),
            duration_seconds,
        ],
    )?;

    Ok(())
}