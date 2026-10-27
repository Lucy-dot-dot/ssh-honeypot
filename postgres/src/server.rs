use crate::config::{DEFAULT_POSTGRES_INTERFACES, PostgresSettings};
use crate::protocol::message::{
    ClientStartup, backend_types, build_authentication_cleartext_password, build_authentication_ok,
    build_backend_key_data_payload, build_command_complete_payload, build_empty_row_description,
    build_parameter_status_payload, command_tag_for, is_empty_query, message_types,
    parse_parse_message, parse_password_message, read_message, read_startup, write_fatal_error,
    write_message, write_single_byte_answer,
};
use chrono::{DateTime, Utc};
use common::abuseipdb::{AbuseIpError, Client as AbuseIpClient};
use common::db::{DbMessage, Module};
use common::ipapi;
use common::tls;
use rand::{RngExt, rng};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use uuid::Uuid;

/// PostgreSQL honeypot server. Mirrors the SSH module: every connection is
/// recorded in conn_track, every auth attempt in auth (module = "postgres")
/// and every query in commands. The server only advertises cleartext
/// password authentication (no MD5, no SCRAM) and does not produce result
/// sets yet.
pub struct PostgresServer {
    db_tx: mpsc::Sender<DbMessage>,
    settings: PostgresSettings,
    tls_acceptor: Option<TlsAcceptor>,
    abuse_ip_client: Option<Arc<AbuseIpClient>>,
    ip_api_client: Option<Arc<ipapi::Client>>,
}

impl PostgresServer {
    pub fn new(
        db_tx: mpsc::Sender<DbMessage>,
        settings: PostgresSettings,
        abuse_ip_client: Option<Arc<AbuseIpClient>>,
        ip_api_client: Option<Arc<ipapi::Client>>,
    ) -> Self {
        let tls_acceptor = tls::build_tls_acceptor(
            "PostgreSQL",
            settings.enable_tls,
            settings.tls_cert.as_deref(),
            settings.tls_key.as_deref(),
        );
        Self {
            db_tx,
            settings,
            tls_acceptor,
            abuse_ip_client,
            ip_api_client,
        }
    }

    /// Accept loop. Runs until the listener is closed.
    pub async fn run_on_listener(self, listener: TcpListener) {
        let local_port = listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(DEFAULT_POSTGRES_INTERFACES[0].port());

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    log::debug!("New PostgreSQL connection from {}", peer);
                    let conn = Connection {
                        db_tx: self.db_tx.clone(),
                        settings: self.settings.clone(),
                        tls_acceptor: self.tls_acceptor.clone(),
                        abuse_ip_client: self.abuse_ip_client.clone(),
                        ip_api_client: self.ip_api_client.clone(),
                    };
                    tokio::spawn(async move {
                        conn.handle_connection(stream, peer, local_port).await;
                    });
                }
                Err(err) => {
                    log::error!("Failed to accept PostgreSQL connection: {}", err);
                }
            }
        }
    }
}

struct Connection {
    db_tx: mpsc::Sender<DbMessage>,
    settings: PostgresSettings,
    tls_acceptor: Option<TlsAcceptor>,
    abuse_ip_client: Option<Arc<AbuseIpClient>>,
    ip_api_client: Option<Arc<ipapi::Client>>,
}

/// Wrapper around a plain TCP stream or a TLS-upgraded stream so the session
/// code works identically on both transport variants.
enum ConnStream {
    Plain(TcpStream),
    Tls(Pin<Box<TlsStream<TcpStream>>>),
}

impl AsyncRead for ConnStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            ConnStream::Tls(stream) => stream.as_mut().poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ConnStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            ConnStream::Tls(stream) => stream.as_mut().poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            ConnStream::Tls(stream) => stream.as_mut().poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            ConnStream::Tls(stream) => stream.as_mut().poll_shutdown(cx),
        }
    }
}

impl Connection {
    async fn handle_connection(&self, stream: TcpStream, peer: SocketAddr, local_port: u16) {
        let ip = peer.ip().to_string();

        // Generate the conn_track UUID client-side so auth attempts on this
        // connection can reference it without any database round-trip
        let conn_uuid = Uuid::new_v4();
        self.record_connect(conn_uuid, &ip, peer.port(), local_port);
        self.warm_ip_caches(&ip);

        if let Err(err) = self.run_session(stream, &ip, peer, conn_uuid).await {
            match err.kind() {
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset => {
                    log::debug!(
                        "PostgreSQL connection from {} closed abruptly: {}",
                        peer,
                        err
                    );
                }
                _ => log::debug!("PostgreSQL session with {} ended: {}", peer, err),
            }
        }
    }

    /// Fire and forget conn_track record
    fn record_connect(&self, id: Uuid, ip: &str, port: u16, local_port: u16) {
        let db_tx = self.db_tx.clone();
        let ip = ip.to_string();
        tokio::spawn(async move {
            match db_tx
                .send(DbMessage::RecordConnect {
                    id,
                    module: Module::Postgres,
                    timestamp: Utc::now(),
                    ip,
                    port,
                    local_port,
                })
                .await
            {
                Ok(_) => log::trace!("Recorded PostgreSQL connection in conn_track"),
                Err(err) => log::error!("Failed to send RecordConnect to db task: {}", err),
            }
        });
    }

    /// Background IP enrichment lookups to populate the caches,
    /// mirroring the behaviour of the SSH module on new connections
    fn warm_ip_caches(&self, ip: &str) {
        if let Some(client) = &self.abuse_ip_client {
            let client = client.clone();
            let ip = ip.to_string();
            tokio::spawn(async move {
                match client.check_ip_with_cache(&ip).await {
                    Ok(_) => log::debug!("Background AbuseIPDB lookup completed for {}", ip),
                    Err(AbuseIpError::RateLimitExceeded(_)) => {
                        log::debug!("Background AbuseIPDB lookup hit rate limit for {}", ip)
                    }
                    Err(e) => log::debug!("Background AbuseIPDB lookup failed for {}: {}", ip, e),
                }
            });
        }
        if let Some(client) = &self.ip_api_client {
            let client = client.clone();
            let ip = ip.to_string();
            tokio::spawn(async move {
                match client.check_ip_with_cache(&ip).await {
                    Ok(_) => log::debug!("Background IPAPI lookup completed for {}", ip),
                    Err(e) => log::debug!("Background IPAPI lookup failed for {}: {}", ip, e),
                }
            });
        }
    }

    /// AbuseIPDB response data for the auth record (same as the SSH module)
    async fn abuseipdb_data(&self, ip: &str) -> Option<serde_json::Value> {
        let client = self.abuse_ip_client.as_ref()?;
        match client.check_ip_with_cache(ip).await {
            Ok(response) => {
                log::info!(
                    "AbuseIPDB check for {}: Confidence: {}%, Country: {}, Tor: {}, Reports: {}",
                    ip,
                    response.data.abuse_confidence_score.unwrap_or(0),
                    response.data.country_code.as_deref().unwrap_or("Unknown"),
                    response.data.is_tor,
                    response.data.total_reports
                );
                serde_json::to_value(&response.data).ok()
            }
            Err(e) => {
                log::warn!("AbuseIPDB check failed for {}: {}", ip, e);
                None
            }
        }
    }

    /// Cached IPAPI response data for the auth record (same as the SSH module)
    async fn ipapi_data(&self, ip: &str) -> Option<serde_json::Value> {
        let client = self.ip_api_client.as_ref()?;
        let cache = client.memory_cache.read().await;
        if let Some(cached) = cache.get(ip) {
            let age = Utc::now() - cached.cached_at;
            if age < chrono::Duration::hours(client.cache_ttl_hours as i64) {
                return serde_json::to_value(&cached.response).ok();
            }
        }
        None
    }

    /// Full PostgreSQL session: startup (with optional SSL upgrade),
    /// cleartext password auth and the command loop. Returns the first IO
    /// error encountered.
    async fn run_session(
        &self,
        stream: TcpStream,
        ip: &str,
        peer: SocketAddr,
        conn_id: Uuid,
    ) -> std::io::Result<()> {
        let mut transport = ConnStream::Plain(stream);

        // 1. Startup phase. SSL and GSS encryption requests are answered
        //    before the real StartupMessage arrives (possibly encrypted).
        let startup = loop {
            let first = match read_startup(&mut transport).await {
                Ok(msg) => msg,
                Err(e) => return Err(e),
            };
            match first {
                ClientStartup::SslRequest => {
                    let Some(acceptor) = &self.tls_acceptor else {
                        log::debug!(
                            "PostgreSQL client {} requested SSL but TLS is disabled on this server",
                            peer
                        );
                        write_single_byte_answer(&mut transport, b'N').await?;
                        continue;
                    };
                    log::debug!(
                        "PostgreSQL client {} is upgrading the connection to SSL",
                        peer
                    );
                    write_single_byte_answer(&mut transport, b'S').await?;
                    let ConnStream::Plain(stream) = transport else {
                        unreachable!(
                            "SSLRequest is only answered before the transport is upgraded"
                        );
                    };
                    match acceptor.accept(stream).await {
                        Ok(tls) => transport = ConnStream::Tls(Box::pin(tls)),
                        Err(err) => {
                            log::debug!("PostgreSQL SSL handshake with {} failed: {}", peer, err);
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("SSL handshake failed: {err}"),
                            ));
                        }
                    }
                }
                ClientStartup::GssEncRequest => {
                    log::debug!(
                        "PostgreSQL client {} requested GSSAPI encryption, unsupported",
                        peer
                    );
                    write_single_byte_answer(&mut transport, b'N').await?;
                }
                ClientStartup::CancelRequest { pid, .. } => {
                    // Best effort like a real server: close silently without
                    // polluting the session statistics
                    log::debug!(
                        "PostgreSQL client {} sent a cancel request for backend pid {}",
                        peer,
                        pid
                    );
                    return Ok(());
                }
                ClientStartup::UnsupportedProtocol { major, minor } => {
                    log::debug!(
                        "PostgreSQL client {} used unsupported protocol {}.{}",
                        peer,
                        major,
                        minor
                    );
                    return write_fatal_error(
                        &mut transport,
                        "28000",
                        &format!(
                            "unsupported frontend protocol {major}.{minor}: server supports 3.0"
                        ),
                    )
                    .await;
                }
                ClientStartup::Startup(startup) => break startup,
            }
        };

        // 2. Parse the StartupMessage
        let Some(username) = startup.get("user").map(str::to_string) else {
            log::debug!(
                "PostgreSQL startup packet from {} without a user name",
                peer
            );
            return write_fatal_error(
                &mut transport,
                "28000",
                "no PostgreSQL user name specified in startup packet",
            )
            .await;
        };
        let database = startup.get("database").map(str::to_string);
        let application_name = startup.get("application_name").map(str::to_string);

        log::info!(
            "PostgreSQL auth attempt - Username: {}, Database: {:?}, Application: {:?}, IP: {}",
            username,
            database,
            application_name,
            peer
        );

        // 3. Cleartext password request. No MD5 and no SCRAM on purpose so
        //    the password arrives in the clear.
        write_message(
            &mut transport,
            backend_types::AUTHENTICATION,
            &build_authentication_cleartext_password(),
        )
        .await?;
        let (msg_type, payload) = read_message(&mut transport).await?;

        let password = if msg_type == message_types::PASSWORD {
            match parse_password_message(&payload) {
                Some(password) => Some(password),
                None => {
                    log::debug!("PostgreSQL client {} sent an empty password", peer);
                    None
                }
            }
        } else {
            log::debug!(
                "PostgreSQL client {} did not answer the cleartext password request with a password message",
                peer
            );
            None
        };

        // 4. Record the auth attempt
        let abuseipdb_data = self.abuseipdb_data(ip).await;
        let ipapi_data = self.ipapi_data(ip).await;
        let auth_id = self
            .record_auth(
                conn_id,
                ip,
                &username,
                password,
                !self.settings.reject_all_auth,
                abuseipdb_data,
                ipapi_data,
            )
            .await;

        // 5. Accept or reject
        if self.settings.reject_all_auth {
            log::debug!("Rejected PostgreSQL authentication attempt");
            return write_fatal_error(
                &mut transport,
                "28P01",
                &format!("password authentication failed for user \"{username}\""),
            )
            .await;
        }
        log::debug!("Accepted PostgreSQL authentication attempt");

        self.write_session_startup_messages(&mut transport, &username, application_name.as_deref())
            .await?;

        // 6. Live session tracking
        let session_id = match &auth_id {
            Some(auth_id) => self.record_session_start(auth_id).await,
            None => None,
        };
        let start_time = Utc::now();

        // 7. Command loop. Queries are logged but answered without result
        //    sets (empty RowDescription + CommandComplete).
        let mut pending_tag: Option<String> = None;
        loop {
            let (msg_type, payload) = match read_message(&mut transport).await {
                Ok(message) => message,
                Err(e) => {
                    self.record_session_end(session_id, start_time).await;
                    return Err(e);
                }
            };

            match msg_type {
                message_types::TERMINATE => {
                    log::debug!("PostgreSQL client {} sent Terminate", peer);
                    self.record_session_end(session_id, start_time).await;
                    return Ok(());
                }
                message_types::QUERY => {
                    let query = String::from_utf8_lossy(&payload);
                    let query = query.trim_end_matches('\0').trim();
                    log::info!("PostgreSQL query from {}: {}", peer, query);

                    self.record_command(&auth_id, query).await;

                    if is_empty_query(query) {
                        write_message(&mut transport, backend_types::EMPTY_QUERY_RESPONSE, b"")
                            .await?;
                    } else {
                        let tag = command_tag_for(query);
                        write_message(
                            &mut transport,
                            backend_types::ROW_DESCRIPTION,
                            &build_empty_row_description(),
                        )
                        .await?;
                        write_message(
                            &mut transport,
                            backend_types::COMMAND_COMPLETE,
                            &build_command_complete_payload(&tag),
                        )
                        .await?;
                    }
                    self.write_ready_for_query(&mut transport).await?;
                }
                message_types::PARSE => {
                    let query = parse_parse_message(&payload)
                        .map(|(_, query)| query)
                        .unwrap_or_default();
                    log::info!("PostgreSQL parse from {}: {}", peer, query.trim());

                    self.record_command(&auth_id, query.trim()).await;

                    pending_tag = if is_empty_query(&query) {
                        None
                    } else {
                        Some(command_tag_for(&query))
                    };
                    write_message(&mut transport, backend_types::PARSE_COMPLETE, b"").await?;
                }
                message_types::BIND => {
                    write_message(&mut transport, backend_types::BIND_COMPLETE, b"").await?;
                }
                message_types::DESCRIBE => {
                    // No statement or portal descriptions available
                    write_message(&mut transport, backend_types::NO_DATA, b"").await?;
                }
                message_types::EXECUTE => {
                    let tag = pending_tag.take().unwrap_or_else(|| "SELECT 0".to_string());
                    write_message(
                        &mut transport,
                        backend_types::COMMAND_COMPLETE,
                        &build_command_complete_payload(&tag),
                    )
                    .await?;
                }
                message_types::CLOSE => {
                    write_message(&mut transport, backend_types::CLOSE_COMPLETE, b"").await?;
                }
                message_types::FLUSH => {
                    // Nothing buffered beyond the answers already flushed
                }
                message_types::SYNC => {
                    self.write_ready_for_query(&mut transport).await?;
                }
                message_types::PASSWORD => {
                    // Unexpected outside of the auth phase; ignore it to stay
                    // in a consistent protocol state
                    log::debug!(
                        "PostgreSQL client {} sent an unexpected password message",
                        peer
                    );
                }
                _ => {
                    self.record_session_end(session_id, start_time).await;
                    log::debug!(
                        "PostgreSQL client {} sent an invalid frontend message type {:?}",
                        peer,
                        char::from(msg_type)
                    );
                    write_fatal_error(
                        &mut transport,
                        "08P01",
                        &format!("invalid frontend message type {}", char::from(msg_type)),
                    )
                    .await?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid frontend message type {}", char::from(msg_type)),
                    ));
                }
            }
        }
    }

    /// AuthenticationOk, ParameterStatus values, BackendKeyData and the
    /// first ReadyForQuery.
    async fn write_session_startup_messages<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        username: &str,
        application_name: Option<&str>,
    ) -> std::io::Result<()> {
        write_message(
            stream,
            backend_types::AUTHENTICATION,
            &build_authentication_ok(),
        )
        .await?;

        let parameters = [
            ("application_name", application_name.unwrap_or_default()),
            ("client_encoding", "UTF8"),
            ("DateStyle", "ISO, MDY"),
            ("integer_datetimes", "on"),
            ("IntervalStyle", "postgres"),
            ("is_superuser", "on"),
            ("server_encoding", "UTF8"),
            ("server_version", self.settings.server_version.as_str()),
            ("session_authorization", username),
            ("standard_conforming_strings", "on"),
            ("TimeZone", "Etc/UTC"),
        ];
        for (key, value) in parameters {
            write_message(
                stream,
                backend_types::PARAMETER_STATUS,
                &build_parameter_status_payload(key, value),
            )
            .await?;
        }

        // Generate the key data in a scope so the thread-local RNG does not
        // live across the following awaits (ThreadRng is not Send)
        let (pid, secret) = {
            let mut rng = rng();
            (rng.random_range(2..=32767), rng.random::<i32>())
        };
        write_message(
            stream,
            backend_types::BACKEND_KEY_DATA,
            &build_backend_key_data_payload(pid, secret),
        )
        .await?;

        self.write_ready_for_query(stream).await
    }

    async fn write_ready_for_query<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
    ) -> std::io::Result<()> {
        write_message(stream, backend_types::READY_FOR_QUERY, b"I").await
    }

    /// Log and record a command in the commands table (fire and forget wait)
    async fn record_command(&self, auth_id: &Option<String>, command: &str) {
        if command.is_empty() {
            return;
        }
        let Some(auth_id) = auth_id else {
            return;
        };
        if let Err(e) = self
            .db_tx
            .send(DbMessage::RecordCommand {
                module: Module::Postgres,
                auth_id: auth_id.clone(),
                timestamp: Utc::now(),
                command: command.to_string(),
            })
            .await
        {
            log::error!("Failed to send RecordCommand to db task: {}", e);
        }
    }

    /// Records the auth attempt and waits for the auth id from the db task.
    /// Returns None if recording failed; the session continues regardless.
    async fn record_auth(
        &self,
        conn_id: Uuid,
        ip: &str,
        username: &str,
        password: Option<String>,
        successful: bool,
        abuseipdb_data: Option<serde_json::Value>,
        ipapi_data: Option<serde_json::Value>,
    ) -> Option<String> {
        // Generate the auth record UUID client-side, so the exact id of the
        // auth table row is known without any database round-trip
        let auth_uuid = Uuid::new_v4();
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        match self
            .db_tx
            .send(DbMessage::RecordAuth {
                id: auth_uuid,
                conn_id,
                module: Module::Postgres,
                timestamp: Utc::now(),
                ip: ip.to_string(),
                username: username.to_string(),
                auth_type: "password".to_string(),
                password,
                public_key: None,
                successful,
                abuseipdb_data,
                ipapi_data,
                response_tx,
            })
            .await
        {
            Ok(_) => match response_rx.await {
                Ok(Ok(auth_id)) => {
                    log::trace!("Recorded PostgreSQL auth with UUID: {}", auth_id);
                    Some(auth_id)
                }
                Ok(Err(e)) => {
                    log::error!("Database error recording PostgreSQL auth: {}", e);
                    None
                }
                Err(e) => {
                    log::error!("Failed to receive PostgreSQL auth response: {}", e);
                    None
                }
            },
            Err(e) => {
                log::error!("Failed to send RecordAuth to db task: {}", e);
                None
            }
        }
    }

    async fn record_session_start(&self, auth_id: &str) -> Option<String> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        match self
            .db_tx
            .send(DbMessage::RecordSessionStart {
                module: Module::Postgres,
                auth_id: auth_id.to_string(),
                start_time: Utc::now(),
                response_tx,
            })
            .await
        {
            Ok(_) => match response_rx.await {
                Ok(Ok(id)) => Some(id),
                Ok(Err(e)) => {
                    log::error!("Database error recording PostgreSQL session start: {}", e);
                    None
                }
                Err(e) => {
                    log::error!("Failed to receive PostgreSQL session start response: {}", e);
                    None
                }
            },
            Err(e) => {
                log::error!("Error sending PostgreSQL session start record: {}", e);
                None
            }
        }
    }

    async fn record_session_end(&self, session_id: Option<String>, start_time: DateTime<Utc>) {
        let Some(session_id) = session_id else {
            return;
        };
        let end_time = Utc::now();
        let duration = end_time - start_time;
        log::info!(
            "PostgreSQL session closed. Start: {}, End: {}, Duration: {}",
            start_time,
            end_time,
            duration
        );
        match self
            .db_tx
            .send(DbMessage::RecordSessionEnd {
                module: Module::Postgres,
                session_id,
                end_time,
                duration_seconds: duration.num_seconds(),
            })
            .await
        {
            Ok(_) => log::trace!("Recorded PostgreSQL session end"),
            Err(e) => log::error!("Error sending PostgreSQL session end record: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PostgresConfig;
    use crate::protocol::message::{PROTOCOL_VERSION_3_0, read_message};
    use tokio::io::AsyncWriteExt;

    /// Connection with a dropped db receiver: every db send fails and is
    /// logged, while the session itself continues. Good enough to exercise
    /// the wire protocol end to end.
    fn test_connection(reject_all_auth: bool) -> Connection {
        let (db_tx, _db_rx) = mpsc::channel::<DbMessage>(16);
        drop(_db_rx);
        let settings = PostgresConfig {
            reject_all_auth: Some(reject_all_auth),
            ..PostgresConfig::default()
        }
        .resolve(true);
        Connection {
            db_tx,
            settings,
            tls_acceptor: None,
            abuse_ip_client: None,
            ip_api_client: None,
        }
    }

    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    fn startup_bytes(params: &[(&str, &str)]) -> Vec<u8> {
        let mut payload = PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
        for (key, value) in params {
            payload.extend_from_slice(key.as_bytes());
            payload.push(0);
            payload.extend_from_slice(value.as_bytes());
            payload.push(0);
        }
        payload.push(0); // parameter list terminator
        let mut message = (payload.len() as u32 + 4).to_be_bytes().to_vec();
        message.extend_from_slice(&payload);
        message
    }

    #[tokio::test]
    async fn cleartext_auth_query_and_terminate() {
        let (mut client, server) = socket_pair().await;
        let conn = test_connection(false);
        let peer: SocketAddr = "127.0.0.1:11111".parse().unwrap();
        let task = tokio::spawn(async move {
            conn.handle_connection(server, peer, 5432).await;
        });

        // StartupMessage
        client
            .write_all(&startup_bytes(&[
                ("user", "postgres"),
                ("database", "honey"),
            ]))
            .await
            .unwrap();

        // Cleartext password request
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::AUTHENTICATION);
        assert_eq!(payload, build_authentication_cleartext_password());

        // PasswordMessage reply
        write_message(&mut client, message_types::PASSWORD, b"hunter2\0")
            .await
            .unwrap();

        // AuthenticationOk
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::AUTHENTICATION);
        assert_eq!(payload, build_authentication_ok());

        // ParameterStatus values until BackendKeyData, then ReadyForQuery
        let mut server_version = None;
        loop {
            let (msg_type, payload) = read_message(&mut client).await.unwrap();
            match msg_type {
                backend_types::PARAMETER_STATUS => {
                    let rendered = String::from_utf8_lossy(&payload);
                    if rendered.starts_with("server_version\0") {
                        server_version = Some(rendered.to_string());
                    }
                }
                backend_types::BACKEND_KEY_DATA => assert_eq!(payload.len(), 8),
                backend_types::READY_FOR_QUERY => {
                    assert_eq!(payload, b"I");
                    break;
                }
                other => panic!("unexpected message type {other:?}"),
            }
        }
        let server_version = server_version.expect("server_version parameter status");
        assert!(server_version.contains("15.6"));

        // Simple query answered with empty RowDescription + CommandComplete
        write_message(
            &mut client,
            message_types::QUERY,
            b"SELECT * FROM secrets;\0",
        )
        .await
        .unwrap();
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::ROW_DESCRIPTION);
        assert_eq!(payload, build_empty_row_description());
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::COMMAND_COMPLETE);
        assert_eq!(payload, build_command_complete_payload("SELECT 0"));
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::READY_FOR_QUERY);
        assert_eq!(payload, b"I");

        // Terminate closes the session cleanly
        write_message(&mut client, message_types::TERMINATE, b"")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("session task did not finish")
            .unwrap();
    }

    #[tokio::test]
    async fn reject_all_auth_answers_fatal_28_p01() {
        let (mut client, server) = socket_pair().await;
        let conn = test_connection(true);
        let peer: SocketAddr = "127.0.0.1:11112".parse().unwrap();
        let task = tokio::spawn(async move {
            conn.handle_connection(server, peer, 5432).await;
        });

        client
            .write_all(&startup_bytes(&[("user", "admin")]))
            .await
            .unwrap();
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::AUTHENTICATION);
        assert_eq!(payload, build_authentication_cleartext_password());
        write_message(&mut client, message_types::PASSWORD, b"guess\0")
            .await
            .unwrap();

        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::ERROR_RESPONSE);
        let rendered = String::from_utf8_lossy(&payload);
        assert!(rendered.contains("C28P01\0"));
        assert!(rendered.contains("password authentication failed for user \"admin\""));

        // The server closes after the fatal error
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("session task did not finish")
            .unwrap();
    }

    #[tokio::test]
    async fn extended_protocol_stays_in_sync() {
        let (mut client, server) = socket_pair().await;
        let conn = test_connection(false);
        let peer: SocketAddr = "127.0.0.1:11113".parse().unwrap();
        let task = tokio::spawn(async move {
            conn.handle_connection(server, peer, 5432).await;
        });

        client
            .write_all(&startup_bytes(&[("user", "postgres")]))
            .await
            .unwrap();

        // Cleartext auth exchange first
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::AUTHENTICATION);
        assert_eq!(payload, build_authentication_cleartext_password());
        write_message(&mut client, message_types::PASSWORD, b"hunter2\0")
            .await
            .unwrap();

        // Drain startup answers up to the first ReadyForQuery
        loop {
            let (msg_type, _) = read_message(&mut client).await.unwrap();
            if msg_type == backend_types::READY_FOR_QUERY {
                break;
            }
        }

        // Parse / Bind / Describe / Execute / Sync
        let mut parse = b"\0".to_vec();
        parse.extend_from_slice(b"INSERT INTO t VALUES (1)\0");
        parse.extend_from_slice(&0i16.to_be_bytes());
        write_message(&mut client, message_types::PARSE, &parse)
            .await
            .unwrap();
        write_message(&mut client, message_types::BIND, b"\0\0\0\0\0")
            .await
            .unwrap();
        write_message(&mut client, message_types::DESCRIBE, b"P\0")
            .await
            .unwrap();
        write_message(&mut client, message_types::EXECUTE, b"\0\0\0\0\0")
            .await
            .unwrap();
        write_message(&mut client, message_types::SYNC, b"")
            .await
            .unwrap();

        let (msg_type, _) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::PARSE_COMPLETE);
        let (msg_type, _) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::BIND_COMPLETE);
        let (msg_type, _) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::NO_DATA);
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::COMMAND_COMPLETE);
        assert_eq!(payload, build_command_complete_payload("INSERT 0 0"));
        let (msg_type, payload) = read_message(&mut client).await.unwrap();
        assert_eq!(msg_type, backend_types::READY_FOR_QUERY);
        assert_eq!(payload, b"I");

        write_message(&mut client, message_types::TERMINATE, b"")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("session task did not finish")
            .unwrap();
    }
}
