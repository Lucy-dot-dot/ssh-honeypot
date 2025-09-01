use chrono::{DateTime, Utc};
use sqlx::{PgPool, query, Row};
use sqlx::types::uuid::Uuid;
use tokio::sync::mpsc;

// Database message types
#[derive(Debug)]
pub enum DbMessage {
    RecordConnect {
        timestamp: DateTime<Utc>,
        ip: String,
    },
    RecordAuth {
        timestamp: DateTime<Utc>,
        ip: String,
        username: String,
        auth_type: String,
        password: Option<String>,
        public_key: Option<String>,
        successful: bool,
        response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    RecordCommand {
        auth_id: String,
        timestamp: DateTime<Utc>,
        command: String,
    },
    RecordSession {
        auth_id: String,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        duration_seconds: i64,
        response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    RecordFileUpload {
        auth_id: String,
        timestamp: DateTime<Utc>,
        filename: String,
        filepath: String,
        file_size: u64,
        file_hash: String,
        claimed_mime_type: Option<String>,
        detected_mime_type: Option<String>,
        format_mismatch: bool,
        file_entropy: Option<f64>,
        binary_data: Vec<u8>,
    },
    Shutdown,
}

// Database handler function that runs in its own task
pub async fn run_db_handler(mut rx: mpsc::Receiver<DbMessage>, pool: PgPool) {
    log::trace!("Starting PostgreSQL database handler");
    
    // Verify database connection
    match pool.acquire().await {
        Ok(_) => {
            log::trace!("Database connection pool initialized successfully");
        },
        Err(e) => {
            log::error!("Failed to acquire database connection: {}", e);
            log::error!("========================================");
            log::error!("🐉 DATABASE FAILED TO INITIALIZE 🐉");
            log::error!("🚨 ATTACK DATA WILL NOT BE SAVED 🚨");
            log::error!("🔥 HERE BE DRAGONS - FIX THIS NOW 🔥");
            log::error!("========================================");
            return;
        }
    }

    // Process database messages
    while let Some(msg) = rx.recv().await {
        log::trace!("Processing database message: {:?}", msg);
        match msg {
            DbMessage::RecordConnect { timestamp, ip } => {
                match record_connect(&pool, timestamp, ip).await {
                    Ok(_) => {
                        log::trace!("Connection recorded");
                    }
                    Err(err) => {
                        log::error!("Failed to record connect event: {}", err);
                    }
                };
            }
            DbMessage::RecordAuth { timestamp, ip, username, auth_type, password, public_key, successful, response_tx } => {
                let result = record_auth(
                    &pool, timestamp, ip, username, auth_type,
                    password, public_key, successful
                ).await;
                
                let response = match result {
                    Ok(auth_id) => Ok(auth_id),
                    Err(e) => {
                        log::error!("Database error recording auth: {}", e);
                        Err(e.to_string())
                    }
                };
                let _ = response_tx.send(response);
            },
            DbMessage::RecordCommand { auth_id, timestamp, command } => {
                if let Err(e) = record_command(&pool, auth_id, timestamp, command).await {
                    log::error!("Database error recording command: {}", e);
                }
            },
            DbMessage::RecordSession { auth_id, start_time, end_time, duration_seconds, response_tx } => {
                let result = record_session(&pool, auth_id, start_time, end_time, duration_seconds).await;
                
                let response = match result {
                    Ok(session_id) => Ok(session_id),
                    Err(e) => {
                        log::error!("Database error recording session: {}", e);
                        Err(e.to_string())
                    }
                };
                let _ = response_tx.send(response);
            },
            DbMessage::RecordFileUpload { auth_id, timestamp, filename, filepath, file_size, file_hash, claimed_mime_type, detected_mime_type, format_mismatch, file_entropy, binary_data } => {
                if let Err(e) = record_file_upload(&pool, auth_id, timestamp, filename, filepath, file_size, file_hash, claimed_mime_type, detected_mime_type, format_mismatch, file_entropy, binary_data).await {
                    log::error!("Database error recording file upload: {}", e);
                }
            },
            DbMessage::Shutdown => {
                log::info!("Database handler shutting down");
                break;
            }
        }
    }
    log::trace!("Database handler stopped");
}

// Initialize database connection pool and run migrations
pub async fn initialize_database_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    log::trace!("Connecting to PostgreSQL database");
    
    let pool = PgPool::connect(database_url).await?;
    
    log::trace!("Running database migrations");
    sqlx::migrate!("./migrations").run(&pool).await?;
    
    log::info!("Database initialized successfully");
    Ok(pool)
}

// Record authentication attempt in database and return the generated UUID
async fn record_auth(
    pool: &PgPool,
    timestamp: DateTime<Utc>,
    ip: String,
    username: String,
    auth_type: String,
    password: Option<String>,
    public_key: Option<String>,
    successful: bool,
) -> Result<String, sqlx::Error> {
    log::trace!("Recording auth attempt: {} from {}", username, ip);
    
    let row = query(
        "INSERT INTO auth (timestamp, ip, username, auth_type, password, public_key, successful)
         VALUES ($1, $2::inet, $3, $4, $5, $6, $7)
         RETURNING id"
    )
    .bind(timestamp)
    .bind(&ip.to_string())
    .bind(username)
    .bind(auth_type)
    .bind(password)
    .bind(public_key)
    .bind(successful)
    .fetch_one(pool)
    .await?;

    let auth_id: Uuid = row.get("id");
    Ok(auth_id.to_string())
}

// Record connection attempt in database
async fn record_connect(
    pool: &PgPool,
    timestamp: DateTime<Utc>,
    ip: String
) -> Result<(), sqlx::Error> {
    log::trace!("Recording connection attempt from {}", ip);

    query("INSERT INTO conn_track (timestamp, ip) VALUES ($1, $2::inet)")
        .bind(timestamp)
        .bind(&ip.to_string())
        .execute(pool)
        .await?;

    Ok(())
}

// Record command in database
async fn record_command(
    pool: &PgPool,
    auth_id: String,
    timestamp: DateTime<Utc>,
    command: String,
) -> Result<(), sqlx::Error> {
    log::trace!("Recording command: {}", command);
    
    query(
        "INSERT INTO commands (auth_id, timestamp, command)
         VALUES ($1::uuid, $2, $3)"
    )
    .bind(&auth_id)
    .bind(timestamp)
    .bind(command)
    .execute(pool)
    .await?;

    Ok(())
}

// Record session in database and return the generated UUID
async fn record_session(
    pool: &PgPool,
    auth_id: String,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    duration_seconds: i64,
) -> Result<String, sqlx::Error> {
    log::trace!("Recording session: {} duration {} seconds", auth_id, duration_seconds);
    
    let row = query(
        "INSERT INTO sessions (auth_id, start_time, end_time, duration_seconds)
         VALUES ($1::uuid, $2, $3, $4)
         RETURNING id"
    )
    .bind(&auth_id)
    .bind(start_time)
    .bind(end_time)
    .bind(duration_seconds)
    .fetch_one(pool)
    .await?;

    let session_id: Uuid = row.get("id");
    Ok(session_id.to_string())
}

// Record file upload in database
async fn record_file_upload(
    pool: &PgPool,
    auth_id: String,
    timestamp: DateTime<Utc>,
    filename: String,
    filepath: String,
    file_size: u64,
    file_hash: String,
    claimed_mime_type: Option<String>,
    detected_mime_type: Option<String>,
    format_mismatch: bool,
    file_entropy: Option<f64>,
    binary_data: Vec<u8>,
) -> Result<(), sqlx::Error> {
    log::trace!("Recording file upload: {} ({} bytes)", filename, binary_data.len());
    
    query(
        "INSERT INTO uploaded_files (auth_id, timestamp, filename, filepath, file_size, file_hash, 
                                   claimed_mime_type, detected_mime_type, format_mismatch, file_entropy, binary_data)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
    )
    .bind(&auth_id)
    .bind(timestamp)
    .bind(filename)
    .bind(filepath)
    .bind(file_size as i64)
    .bind(file_hash)
    .bind(claimed_mime_type)
    .bind(detected_mime_type)
    .bind(format_mismatch)
    .bind(file_entropy)
    .bind(binary_data)
    .execute(pool)
    .await?;

    Ok(())
}

// Record AbuseIPDB check result in database
pub async fn record_abuse_ip_check(
    pool: &PgPool,
    ip: String,
    timestamp: DateTime<Utc>,
    abuse_confidence_score: Option<u8>,
    country_code: Option<String>,
    is_tor: bool,
    is_whitelisted: Option<bool>,
    total_reports: u32,
    response_data: String,
) -> Result<(), sqlx::Error> {
    let response_json: serde_json::Value = match serde_json::from_str(&response_data) {
        Ok(val) => {
            log::trace!("Decoded abuse ipdb json response from string");
            val
        },
        Err(err) => {
            log::error!("Failed to decode json. We do not save malformed json to db: {}", err);
            return Ok(())
        }
    };
    
    log::trace!("Recording AbuseIPDB check for IP: {}", ip);
    
    query(
        "INSERT INTO abuse_ip_cache (ip, timestamp, abuse_confidence_score, country_code, is_tor, is_whitelisted, total_reports, response_data)
         VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (ip) DO UPDATE SET
            timestamp = EXCLUDED.timestamp,
            abuse_confidence_score = EXCLUDED.abuse_confidence_score,
            country_code = EXCLUDED.country_code,
            is_tor = EXCLUDED.is_tor,
            is_whitelisted = EXCLUDED.is_whitelisted,
            total_reports = EXCLUDED.total_reports,
            response_data = EXCLUDED.response_data"
    )
    .bind(&ip.to_string())
    .bind(timestamp)
    .bind(abuse_confidence_score.map(|s| s as i16))
    .bind(country_code)
    .bind(is_tor)
    .bind(is_whitelisted)
    .bind(total_reports as i32)
    .bind(response_json)
    .execute(pool)
    .await?;

    Ok(())
}

// Get AbuseIPDB check result from database with automatic expiration
pub async fn get_abuse_ip_check(
    pool: &PgPool,
    ip: &str,
    cache_ttl_hours: u8,
) -> Result<Option<(DateTime<Utc>, crate::abuseipdb::CheckResponseData)>, sqlx::Error> {
    
    let result = query(
        "SELECT timestamp, response_data 
         FROM abuse_ip_cache 
         WHERE ip = $1::inet
           AND timestamp > NOW() - INTERVAL '1 hour' * $2"
    )
    .bind(&ip.to_string())
    .bind(cache_ttl_hours as i32)
    .fetch_optional(pool)
    .await?;
    
    match result {
        Some(row) => {
            let timestamp: DateTime<Utc> = row.get("timestamp");
            let response_data: serde_json::Value = row.get("response_data");
            
            match serde_json::from_value::<crate::abuseipdb::CheckResponseData>(response_data) {
                Ok(response) => {
                    log::debug!("AbuseIPDB cache hit from database for IP: {}", ip);
                    Ok(Some((timestamp, response)))
                },
                Err(e) => {
                    log::error!("Failed to deserialize cached AbuseIPDB data for {}: {}", ip, e);
                    Ok(None)
                }
            }
        },
        None => {
            log::debug!("No valid AbuseIPDB cache entry found for IP: {}", ip);
            Ok(None)
        }
    }
}

// Record IPAPI check result in database
pub async fn record_ipapi_check(
    pool: &PgPool,
    ip: String,
    timestamp: DateTime<Utc>,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    region_name: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    as_info: Option<String>,
    response_data: String,
) -> Result<(), sqlx::Error> {
    let response_json: serde_json::Value = match serde_json::from_str(&response_data) {
        Ok(val) => {
            log::trace!("Decoded abuse ip-api json response from string");
            val
        },
        Err(err) => {
            log::error!("Failed to decode json. We do not save malformed json to db: {}", err);
            return Ok(())
        }
    };
    
    log::trace!("Recording IPAPI check for IP: {}", ip);
    
    query(
        "INSERT INTO ipapi_cache (ip, timestamp, country, country_code, region, region_name, city, zip, lat, lon, timezone, isp, org, as_info, response_data)
         VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         ON CONFLICT (ip) DO UPDATE SET
            timestamp = EXCLUDED.timestamp,
            country = EXCLUDED.country,
            country_code = EXCLUDED.country_code,
            region = EXCLUDED.region,
            region_name = EXCLUDED.region_name,
            city = EXCLUDED.city,
            zip = EXCLUDED.zip,
            lat = EXCLUDED.lat,
            lon = EXCLUDED.lon,
            timezone = EXCLUDED.timezone,
            isp = EXCLUDED.isp,
            org = EXCLUDED.org,
            as_info = EXCLUDED.as_info,
            response_data = EXCLUDED.response_data"
    )
    .bind(&ip.to_string())
    .bind(timestamp)
    .bind(country)
    .bind(country_code)
    .bind(region)
    .bind(region_name)
    .bind(city)
    .bind(zip)
    .bind(lat)
    .bind(lon)
    .bind(timezone)
    .bind(isp)
    .bind(org)
    .bind(as_info)
    .bind(response_json)
    .execute(pool)
    .await?;

    Ok(())
}

// Get IPAPI check result from database with automatic expiration
pub async fn get_ipapi_check(
    pool: &PgPool,
    ip: &str,
    cache_ttl_hours: u8,
) -> Result<Option<(DateTime<Utc>, crate::ipapi::IpApiResponse)>, sqlx::Error> {
    
    let result = query(
        "SELECT timestamp, response_data 
         FROM ipapi_cache 
         WHERE ip = $1::inet
           AND timestamp > NOW() - INTERVAL '1 hour' * $2"
    )
    .bind(&ip.to_string())
    .bind(cache_ttl_hours as i32)
    .fetch_optional(pool)
    .await?;
    
    match result {
        Some(row) => {
            let timestamp: DateTime<Utc> = row.get("timestamp");
            let response_data: serde_json::Value = row.get("response_data");
            
            match serde_json::from_value::<crate::ipapi::IpApiResponse>(response_data) {
                Ok(response) => {
                    log::debug!("IPAPI cache hit from database for IP: {}", ip);
                    Ok(Some((timestamp, response)))
                },
                Err(e) => {
                    log::error!("Failed to deserialize cached IPAPI data for {}: {}", ip, e);
                    Ok(None)
                }
            }
        },
        None => {
            log::debug!("No valid IPAPI cache entry found for IP: {}", ip);
            Ok(None)
        }
    }
}