use crate::config::MysqlSettings;
use crate::protocol::constants::{CLEAR_PASSWORD_PLUGIN, commands, error_codes};
use crate::protocol::handshake::{
    build_auth_switch_request, build_err, build_initial_handshake, build_ok, build_statistics,
    is_ssl_request, parse_clear_password, parse_handshake_response,
};
use crate::protocol::packet::{read_packet, write_packet};
use chrono::{DateTime, Utc};
use common::abuseipdb::{AbuseIpError, Client as AbuseIpClient};
use common::db::{DbMessage, Module};
use common::ipapi;
use common::tls;
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

/// MySQL honeypot server. Mirrors the SSH module: every connection is
/// recorded in conn_track, every auth attempt in auth (module = "mysql") and
/// every query in commands. The simulated SQL shell does not produce result
/// sets yet and answers everything with an empty OK packet.
pub struct MysqlServer {
    db_tx: mpsc::Sender<DbMessage>,
    settings: MysqlSettings,
    tls_acceptor: Option<TlsAcceptor>,
    abuse_ip_client: Option<Arc<AbuseIpClient>>,
    ip_api_client: Option<Arc<ipapi::Client>>,
}

impl MysqlServer {
    pub fn new(
        db_tx: mpsc::Sender<DbMessage>,
        settings: MysqlSettings,
        abuse_ip_client: Option<Arc<AbuseIpClient>>,
        ip_api_client: Option<Arc<ipapi::Client>>,
    ) -> Self {
        let tls_acceptor = tls::build_tls_acceptor(
            "MySQL",
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
            .unwrap_or(crate::config::DEFAULT_MYSQL_INTERFACES[0].port());

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    log::debug!("New MySQL connection from {}", peer);
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
                    log::error!("Failed to accept MySQL connection: {}", err);
                }
            }
        }
    }
}

struct Connection {
    db_tx: mpsc::Sender<DbMessage>,
    settings: MysqlSettings,
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

        self.record_connect(&ip, peer.port(), local_port);
        self.warm_ip_caches(&ip);

        if let Err(err) = self.run_session(stream, &ip, peer).await {
            match err.kind() {
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset => {
                    log::debug!("MySQL connection from {} closed abruptly: {}", peer, err);
                }
                _ => log::debug!("MySQL session with {} ended: {}", peer, err),
            }
        }
    }

    /// Fire and forget conn_track record
    fn record_connect(&self, ip: &str, port: u16, local_port: u16) {
        let db_tx = self.db_tx.clone();
        let ip = ip.to_string();
        tokio::spawn(async move {
            match db_tx
                .send(DbMessage::RecordConnect {
                    timestamp: Utc::now(),
                    ip,
                    port,
                    local_port,
                })
                .await
            {
                Ok(_) => log::trace!("Recorded MySQL connection in conn_track"),
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

    /// Capabilities advertised in the greeting. CLIENT_SSL is only offered
    /// when a TLS acceptor is available so clients do not attempt an
    /// upgrade the server cannot perform.
    fn server_capabilities(&self) -> u32 {
        let base = crate::protocol::constants::capabilities::SERVER_CAPABILITIES;
        if self.tls_acceptor.is_some() {
            base | crate::protocol::constants::capabilities::CLIENT_SSL
        } else {
            base
        }
    }

    /// Full MySQL session: handshake, optional TLS upgrade, auth (with clear
    /// password auth switch) and the command loop. Returns the first IO
    /// error encountered.
    async fn run_session(
        &self,
        mut stream: TcpStream,
        ip: &str,
        peer: SocketAddr,
    ) -> std::io::Result<()> {
        let mut seq = 0u8;

        // 1. Server greeting
        let (payload, _seed) =
            build_initial_handshake(&self.settings.server_version, self.server_capabilities());
        write_packet(&mut stream, &mut seq, &payload).await?;

        // 2. Client handshake response; an SSL request upgrades the
        //    transport before the real handshake response is read
        let response = read_packet(&mut stream, &mut seq).await?;
        let mut transport = if is_ssl_request(&response) {
            let Some(acceptor) = &self.tls_acceptor else {
                log::debug!(
                    "MySQL client {} requested TLS but TLS is disabled on this server",
                    peer
                );
                return write_packet(
                    &mut stream,
                    &mut seq,
                    &build_err(
                        error_codes::ER_BAD_HS_ERROR,
                        "28000",
                        "Bad handshake (TLS not supported by this server)",
                    ),
                )
                .await;
            };
            log::debug!("MySQL client {} is upgrading the connection to TLS", peer);
            match acceptor.accept(stream).await {
                Ok(tls) => ConnStream::Tls(Box::pin(tls)),
                Err(err) => {
                    log::debug!("MySQL TLS handshake with {} failed: {}", peer, err);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("TLS handshake failed: {err}"),
                    ));
                }
            }
        } else {
            ConnStream::Plain(stream)
        };

        // 3. The actual handshake response arrives over the (possibly
        //    encrypted) transport
        let response = if matches!(transport, ConnStream::Tls(_)) {
            read_packet(&mut transport, &mut seq).await?
        } else {
            response
        };

        let handshake = match parse_handshake_response(&response) {
            Ok(hs) => hs,
            Err(e) => {
                log::debug!("Malformed MySQL handshake from {}: {}", peer, e);
                return write_packet(
                    &mut transport,
                    &mut seq,
                    &build_err(error_codes::ER_BAD_HS_ERROR, "28000", "Bad handshake"),
                )
                .await;
            }
        };

        log::info!(
            "MySQL auth attempt - Username: {}, Database: {:?}, Client plugin: {:?}, IP: {}",
            handshake.username,
            handshake.database,
            handshake.auth_plugin,
            peer
        );

        // 3. Auth switch to mysql_clear_password so clients transmit the
        //    password in cleartext instead of an unrecoverable scramble
        write_packet(
            &mut transport,
            &mut seq,
            &build_auth_switch_request(CLEAR_PASSWORD_PLUGIN),
        )
        .await?;
        let switch_response = read_packet(&mut transport, &mut seq).await?;

        let password = parse_clear_password(&switch_response);
        if password.is_none() {
            // Client answered with something else (e.g. another native
            // password scramble). Nothing usable to store, accept anyway.
            log::debug!(
                "MySQL client {} did not answer the clear password auth switch with text",
                peer
            );
        }

        // 4. Record the auth attempt
        let abuseipdb_data = self.abuseipdb_data(ip).await;
        let ipapi_data = self.ipapi_data(ip).await;
        let auth_id = self
            .record_auth(
                ip,
                &handshake.username,
                password,
                !self.settings.reject_all_auth,
                abuseipdb_data,
                ipapi_data,
            )
            .await;

        // 5. Accept or reject
        if self.settings.reject_all_auth {
            log::debug!("Rejected MySQL authentication attempt");
            return write_packet(
                &mut transport,
                &mut seq,
                &build_err(
                    error_codes::ER_ACCESS_DENIED_ERROR,
                    "28000",
                    &format!(
                        "Access denied for user '{}'@'{}' (using password: YES)",
                        handshake.username,
                        peer.ip()
                    ),
                ),
            )
            .await;
        }
        log::debug!("Accepted MySQL authentication attempt");
        write_packet(&mut transport, &mut seq, &build_ok(handshake.protocol_41)).await?;

        // 6. Live session tracking
        let session_id = match &auth_id {
            Some(auth_id) => self.record_session_start(auth_id).await,
            None => None,
        };
        let start_time = Utc::now();

        // 7. Command loop. Queries are logged but answered with an empty OK.
        loop {
            let packet = match read_packet(&mut transport, &mut seq).await {
                Ok(p) => p,
                Err(e) => {
                    self.record_session_end(session_id, start_time).await;
                    return Err(e);
                }
            };

            if packet.is_empty() {
                self.record_session_end(session_id, start_time).await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "empty command packet",
                ));
            }

            match packet[0] {
                commands::COM_QUIT => {
                    log::debug!("MySQL client {} sent COM_QUIT", peer);
                    self.record_session_end(session_id, start_time).await;
                    return Ok(());
                }
                commands::COM_QUERY => {
                    let query = String::from_utf8_lossy(&packet[1..]);
                    let query = query.trim_end_matches('\0').trim();
                    log::info!("MySQL query from {}: {}", peer, query);

                    if let Some(auth_id) = &auth_id
                        && let Err(e) = self
                            .db_tx
                            .send(DbMessage::RecordCommand {
                                auth_id: auth_id.clone(),
                                timestamp: Utc::now(),
                                command: query.to_string(),
                            })
                            .await
                    {
                        log::error!("Failed to send RecordCommand to db task: {}", e);
                    }

                    write_packet(&mut transport, &mut seq, &build_ok(true)).await?;
                }
                commands::COM_PING => {
                    write_packet(&mut transport, &mut seq, &build_ok(true)).await?;
                }
                commands::COM_INIT_DB => {
                    log::debug!("MySQL client {} sent COM_INIT_DB", peer);
                    write_packet(&mut transport, &mut seq, &build_ok(true)).await?;
                }
                commands::COM_FIELD_LIST | commands::COM_PROCESS_INFO => {
                    // Deprecated commands without a simulated result set
                    write_packet(&mut transport, &mut seq, &build_ok(true)).await?;
                }
                commands::COM_STATISTICS => {
                    let uptime = (Utc::now() - start_time).num_seconds().max(0) as u64;
                    write_packet(&mut transport, &mut seq, &build_statistics(uptime)).await?;
                }
                _ => {
                    write_packet(
                        &mut transport,
                        &mut seq,
                        &build_err(
                            error_codes::ER_UNKNOWN_COM_ERROR,
                            "08S01",
                            "Unknown command",
                        ),
                    )
                    .await?;
                }
            }
        }
    }

    /// Records the auth attempt and waits for the auth id from the db task.
    /// Returns None if recording failed; the session continues regardless.
    async fn record_auth(
        &self,
        ip: &str,
        username: &str,
        password: Option<String>,
        successful: bool,
        abuseipdb_data: Option<serde_json::Value>,
        ipapi_data: Option<serde_json::Value>,
    ) -> Option<String> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        match self
            .db_tx
            .send(DbMessage::RecordAuth {
                module: Module::Mysql,
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
                    log::trace!("Recorded MySQL auth with UUID: {}", auth_id);
                    Some(auth_id)
                }
                Ok(Err(e)) => {
                    log::error!("Database error recording MySQL auth: {}", e);
                    None
                }
                Err(e) => {
                    log::error!("Failed to receive MySQL auth response: {}", e);
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
                auth_id: auth_id.to_string(),
                start_time: Utc::now(),
                response_tx,
            })
            .await
        {
            Ok(_) => match response_rx.await {
                Ok(Ok(id)) => Some(id),
                Ok(Err(e)) => {
                    log::error!("Database error recording MySQL session start: {}", e);
                    None
                }
                Err(e) => {
                    log::error!("Failed to receive MySQL session start response: {}", e);
                    None
                }
            },
            Err(e) => {
                log::error!("Error sending MySQL session start record: {}", e);
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
            "MySQL session closed. Start: {}, End: {}, Duration: {}",
            start_time,
            end_time,
            duration
        );
        match self
            .db_tx
            .send(DbMessage::RecordSessionEnd {
                session_id,
                end_time,
                duration_seconds: duration.num_seconds(),
            })
            .await
        {
            Ok(_) => log::trace!("Recorded MySQL session end"),
            Err(e) => log::error!("Error sending MySQL session end record: {}", e),
        }
    }
}
