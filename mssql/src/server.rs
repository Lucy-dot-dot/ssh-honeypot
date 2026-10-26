use crate::config::MssqlSettings;
use crate::protocol::login7::{Login7, fedauth_mechanism};
use crate::protocol::ntlm::{NtlmAuthenticate, build_challenge, is_ntlm_negotiate};
use crate::protocol::packet::{
    MAX_PAYLOAD_LEN, is_tls_client_hello, packet_type, read_packet, write_packet,
};
use crate::protocol::prelogin;
use crate::protocol::tokens::{self, done_status, envchange_type};
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
use uuid::Uuid;

/// MSSQL (TDS) honeypot server. Mirrors the SSH and MySQL modules: every
/// connection is recorded in conn_track, every login attempt in auth
/// (module = "mssql") and every post-login batch/RPC request in commands.
/// The simulated server does not produce result sets; the goal is capture
/// of credentials (SQL auth, NTLM, Azure AD) and request intelligence.
pub struct MssqlServer {
    db_tx: mpsc::Sender<DbMessage>,
    settings: MssqlSettings,
    tls_acceptor: Option<TlsAcceptor>,
    abuse_ip_client: Option<Arc<AbuseIpClient>>,
    ip_api_client: Option<Arc<ipapi::Client>>,
}

impl MssqlServer {
    pub fn new(
        db_tx: mpsc::Sender<DbMessage>,
        settings: MssqlSettings,
        abuse_ip_client: Option<Arc<AbuseIpClient>>,
        ip_api_client: Option<Arc<ipapi::Client>>,
    ) -> Self {
        let tls_acceptor = tls::build_tls_acceptor(
            "MSSQL",
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
            .unwrap_or(crate::config::DEFAULT_MSSQL_INTERFACES[0].port());

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    log::debug!("New MSSQL connection from {}", peer);
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
                    log::error!("Failed to accept MSSQL connection: {}", err);
                }
            }
        }
    }
}

struct Connection {
    db_tx: mpsc::Sender<DbMessage>,
    settings: MssqlSettings,
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
                    log::debug!("MSSQL connection from {} closed abruptly: {}", peer, err);
                }
                _ => log::debug!("MSSQL session with {} ended: {}", peer, err),
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
                    module: Module::Mssql,
                    timestamp: Utc::now(),
                    ip,
                    port,
                    local_port,
                })
                .await
            {
                Ok(_) => log::trace!("Recorded MSSQL connection in conn_track"),
                Err(err) => log::error!("Failed to send RecordConnect to db task: {}", err),
            }
        });
    }

    /// Background IP enrichment lookups to populate the caches,
    /// mirroring the behaviour of the SSH and MySQL modules
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

    /// TDS version we present (TDS 7.4) and the parsed server version
    fn tds_version(&self) -> u32 {
        0x0400_0000
    }

    fn version_tuple(&self) -> (u8, u8, u16, u16) {
        prelogin::parse_version_string(&self.settings.server_version)
    }

    /// Full MSSQL session: optional TDS 8.0 TLS-first handshake, prelogin,
    /// optional login encryption, LOGIN7 authentication (SQL auth, NTLM or
    /// Azure AD) and the post-login request loop. Returns the first IO
    /// error encountered.
    async fn run_session(&self, stream: TcpStream, ip: &str, peer: SocketAddr) -> io::Result<()> {
        let mut transport = if peek_is_tls_client_hello(&stream).await? {
            // TDS 8.0 "strict encryption": TLS before prelogin
            let Some(acceptor) = &self.tls_acceptor else {
                log::debug!(
                    "MSSQL client {} sent a TLS handshake but TLS is disabled",
                    peer
                );
                return Ok(());
            };
            let tls_stream = acceptor.accept(stream).await?;
            log::debug!(
                "MSSQL connection from {} upgraded to TLS (pre-prelogin)",
                peer
            );
            ConnStream::Tls(Box::pin(tls_stream))
        } else {
            ConnStream::Plain(stream)
        };

        // 1. Prelogin negotiation (always plaintext unless already TLS)
        let request = read_packet(&mut transport).await?;
        if request.ptype != packet_type::PRELOGIN {
            log::debug!(
                "MSSQL client {} sent packet type {:#04x} instead of PRELOGIN",
                peer,
                request.ptype
            );
            return Ok(());
        }
        let prelogin_request = prelogin::parse_request(&request.payload);
        let encrypt_flag = if self.tls_acceptor.is_some() {
            prelogin::encryption::ENCRYPT_OFF
        } else {
            prelogin::encryption::ENCRYPT_NOT_SUP
        };
        let response = prelogin::build_response(
            encrypt_flag,
            self.version_tuple(),
            prelogin_request.mars.is_some(),
        );
        write_packet(
            &mut transport,
            request.channel,
            packet_type::PRELOGIN,
            &response,
        )
        .await?;

        // 2. Voluntary TLS upgrade (clients with Encrypt=Strict on a
        //    non-strict server, or EncryptLogin variants)
        let want_upgrade = matches!(transport, ConnStream::Plain(_))
            && peek_is_tls_client_hello_plain(&transport).await?;
        if want_upgrade {
            let ConnStream::Plain(stream) = transport else {
                unreachable!("checked above");
            };
            let Some(acceptor) = self.tls_acceptor.as_ref() else {
                // Unreachable in practice: without an acceptor we advertise
                // ENCRYPT_NOT_SUP and never see a ClientHello here
                return Ok(());
            };
            let tls_stream = acceptor.accept(stream).await?;
            log::debug!(
                "MSSQL connection from {} upgraded to TLS (post-prelogin)",
                peer
            );
            transport = ConnStream::Tls(Box::pin(tls_stream));
        }

        // 3. Authentication: LOGIN7 (followed by an SSPI exchange when the
        //    client uses integrated security)
        let login_packet = read_packet(&mut transport).await?;
        if login_packet.ptype != packet_type::LOGIN7 {
            log::debug!(
                "MSSQL client {} sent packet type {:#04x} instead of LOGIN7",
                peer,
                login_packet.ptype
            );
            return Ok(());
        }
        let Some(login) = Login7::parse(&login_packet.payload) else {
            log::debug!("MSSQL client {} sent a malformed LOGIN7 packet", peer);
            return Ok(());
        };
        log::info!(
            "MSSQL login attempt from {}: client={:?} app={:?} host={:?} user={:?} db={:?} tds={}.{}",
            peer,
            login.client_name,
            login.app_name,
            login.server_name,
            login.username,
            login.database,
            login.tds_version_major,
            login.tds_version_minor
        );

        // Resolve the authentication method and captured credentials
        let mut auth = match self
            .resolve_auth(&mut transport, &login, login_packet.channel, peer)
            .await?
        {
            Some(auth) => auth,
            // Client walked away mid-exchange (e.g. unsupported mechanism)
            None => return Ok(()),
        };

        log::info!(
            "MSSQL authentication from {}: method={} user={} password={}",
            peer,
            auth.auth_type,
            auth.username,
            auth.password
                .as_deref()
                .map(|p| if p.len() > 64 { &p[..64] } else { p })
                .unwrap_or("<none>")
        );

        let successful = !self.settings.reject_all_auth;
        let abuseipdb_data = self.abuseipdb_data(ip).await;
        let ipapi_data = self.ipapi_data(ip).await;
        let auth_id = self
            .record_auth(
                ip,
                &auth.username,
                auth.password.take(),
                successful,
                &auth.auth_type,
                abuseipdb_data,
                ipapi_data,
            )
            .await;

        if !successful {
            let error = tokens::build_login_failed(&auth.username, &self.settings.host_name);
            write_packet(
                &mut transport,
                login_packet.channel,
                packet_type::TABULAR_RESULT,
                &error,
            )
            .await?;
            return Ok(());
        }

        // 4. Accept: LOGINACK + ENVCHANGE(database, packet size) + DONE
        let packet_size = login.packet_size.clamp(512, MAX_PAYLOAD_LEN as u32);
        let token_stream = tokens::token_stream(vec![
            tokens::build_login_ack(self.tds_version(), self.version_tuple()),
            tokens::build_envchange(envchange_type::DATABASE, "master", ""),
            tokens::build_envchange(
                envchange_type::PACKET_SIZE,
                &packet_size.to_string(),
                &packet_size.to_string(),
            ),
            tokens::build_done(done_status::DONE_FINAL),
        ]);
        write_packet(
            &mut transport,
            login_packet.channel,
            packet_type::TABULAR_RESULT,
            &token_stream,
        )
        .await?;

        // 5. Post-auth request loop
        let start_time = Utc::now();
        let session_id = match &auth_id {
            Some(auth_id) => self.record_session_start(auth_id).await,
            None => None,
        };
        let result = self
            .request_loop(&mut transport, login_packet.channel, auth_id.as_ref(), peer)
            .await;
        self.record_session_end(session_id, start_time).await;
        result
    }

    /// Performs any follow-up SSPI exchange and produces the auth record
    /// (username, captured credential, auth_type). Returns None when the
    /// client disconnected mid-exchange.
    async fn resolve_auth(
        &self,
        transport: &mut ConnStream,
        login: &Login7,
        channel: u16,
        peer: SocketAddr,
    ) -> io::Result<Option<AuthCapture>> {
        if login.integrated_security {
            let Some(sspi) = &login.sspi else {
                // fIntSecurity without an SSPI blob: nothing to capture
                log::debug!(
                    "MSSQL client {} requested integrated security without an SSPI blob",
                    peer
                );
                return Ok(Some(AuthCapture {
                    username: login.username.clone().unwrap_or_default(),
                    password: None,
                    auth_type: "sspi".to_string(),
                }));
            };

            if !is_ntlm_negotiate(sspi) {
                // Kerberos or another GSS-API mechanism: record and let the
                // caller reject with 18452 (untrusted domain)
                log::info!(
                    "MSSQL client {} used a non-NTLM SSPI mechanism ({} bytes, starts {:02x?})",
                    peer,
                    sspi.len(),
                    &sspi[..sspi.len().min(8)]
                );
                return Ok(Some(AuthCapture {
                    username: login.username.clone().unwrap_or_default(),
                    password: None,
                    auth_type: "sspi".to_string(),
                }));
            }

            // NTLM: answer the NEGOTIATE (type 1) with a CHALLENGE (type 2)
            let server_challenge: [u8; 8] = rand::random();
            let challenge = build_challenge(
                &server_challenge,
                &self.settings.host_name,
                &self.settings.domain_name,
                &self.settings.host_name,
                &self.settings.domain_name,
                Utc::now().timestamp().max(0) as u64,
            );
            write_packet(transport, channel, packet_type::TABULAR_RESULT, &challenge).await?;

            // The AUTHENTICATE (type 3) arrives in an SSPI packet (0x11),
            // though some stacks re-use LOGIN7 (0x10)
            let response = read_packet(transport).await?;
            let blob: Option<Vec<u8>> = match response.ptype {
                packet_type::SSPI_AUTH => Some(response.payload),
                packet_type::LOGIN7 => Login7::parse(&response.payload).and_then(|l| l.sspi),
                _ => None,
            };
            let Some(blob) = blob else {
                log::debug!(
                    "MSSQL client {} sent packet type {:#04x} instead of the NTLM AUTHENTICATE",
                    peer,
                    response.ptype
                );
                return Ok(None);
            };

            let authenticate = NtlmAuthenticate::parse(&blob).or_else(|| {
                // SPNEGO-wrapped type 3 message
                let start = crate::protocol::ntlm::extract_ntlmssp(&blob)?;
                NtlmAuthenticate::parse(start)
            });
            let Some(authenticate) = authenticate else {
                log::debug!("MSSQL client {} sent an unparseable NTLM response", peer);
                return Ok(Some(AuthCapture {
                    username: login.username.clone().unwrap_or_default(),
                    password: None,
                    auth_type: "ntlm".to_string(),
                }));
            };

            let display_user = if authenticate.domain.is_empty() {
                authenticate.user.clone()
            } else {
                format!("{}\\{}", authenticate.domain, authenticate.user)
            };
            log::info!(
                "MSSQL NTLM authentication from {}: user={} workstation={} {}",
                peer,
                display_user,
                authenticate.workstation,
                if authenticate.is_ntlmv2 {
                    "NTLMv2"
                } else {
                    "NTLMv1"
                }
            );

            // Net-NTLMv2 hash in hashcat -m 5600 format; nothing recoverable
            // from legacy v1 responses beyond the recorded identities
            let hash = authenticate.net_ntlmv2_string(&server_challenge);
            return Ok(Some(AuthCapture {
                username: display_user,
                password: hash,
                auth_type: "ntlm".to_string(),
            }));
        }

        match login.fedauth_mechanism {
            fedauth_mechanism::TOKEN => {
                // Bearer token travels in the SSPI slot, usually a JWT
                let token = login
                    .sspi
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .map(|s| s.trim().to_string());
                Ok(Some(AuthCapture {
                    username: login.username.clone().unwrap_or_default(),
                    password: token,
                    auth_type: "azure_ad_token".to_string(),
                }))
            }
            fedauth_mechanism::PASSWORD => Ok(Some(AuthCapture {
                username: login.username.clone().unwrap_or_default(),
                password: login.password.clone(),
                auth_type: "azure_ad_password".to_string(),
            })),
            _ => Ok(Some(AuthCapture {
                username: login.username.clone().unwrap_or_default(),
                password: login.password.clone(),
                auth_type: "password".to_string(),
            })),
        }
    }

    /// Post-authentication request loop: logs SQL batches and RPC calls
    /// into the commands table, answers everything without result sets.
    async fn request_loop(
        &self,
        transport: &mut ConnStream,
        channel: u16,
        auth_id: Option<&String>,
        peer: SocketAddr,
    ) -> io::Result<()> {
        loop {
            let packet = read_packet(transport).await?;
            match packet.ptype {
                packet_type::SQL_BATCH => {
                    let query = decode_utf16le(&packet.payload);
                    let query = query.trim_end_matches('\0').trim();
                    log::info!("MSSQL batch from {}: {}", peer, query);
                    self.record_command(auth_id, query).await;
                    write_packet(
                        transport,
                        channel,
                        packet_type::TABULAR_RESULT,
                        &tokens::build_done(done_status::DONE_FINAL),
                    )
                    .await?;
                }
                packet_type::RPC => {
                    let proc_name = parse_rpc_name(&packet.payload);
                    log::info!("MSSQL RPC from {}: {}", peer, proc_name);
                    self.record_command(auth_id, &proc_name).await;
                    write_packet(
                        transport,
                        channel,
                        packet_type::TABULAR_RESULT,
                        &tokens::build_done(done_status::DONE_FINAL),
                    )
                    .await?;
                }
                packet_type::ATTENTION => {
                    log::debug!("MSSQL client {} sent ATTENTION (cancel)", peer);
                    write_packet(
                        transport,
                        channel,
                        packet_type::TABULAR_RESULT,
                        &tokens::build_done(done_status::DONE_ATTN),
                    )
                    .await?;
                }
                packet_type::PRELOGIN => {
                    // Some drivers re-negotiate after a reconnect; keep
                    // answering instead of dying
                    let response = prelogin::build_response(
                        if self.tls_acceptor.is_some() {
                            prelogin::encryption::ENCRYPT_OFF
                        } else {
                            prelogin::encryption::ENCRYPT_NOT_SUP
                        },
                        self.version_tuple(),
                        false,
                    );
                    write_packet(transport, channel, packet_type::PRELOGIN, &response).await?;
                }
                packet_type::LOGIN7 => {
                    log::debug!("MSSQL client {} re-sent LOGIN7 mid-session", peer);
                }
                packet_type::FEDAUTH => {
                    log::debug!("MSSQL client {} sent a FEDAUTH continuation", peer);
                    write_packet(
                        transport,
                        channel,
                        packet_type::TABULAR_RESULT,
                        &tokens::build_done(done_status::DONE_FINAL),
                    )
                    .await?;
                }
                other => {
                    log::debug!(
                        "MSSQL client {} sent unsupported packet type {:#04x}",
                        peer,
                        other
                    );
                    let error = tokens::build_error(
                        18,
                        1,
                        20,
                        "Unsupported packet type.",
                        &self.settings.host_name,
                        "",
                        0,
                    );
                    let stream = tokens::token_stream(vec![
                        error,
                        tokens::build_done(done_status::DONE_ERROR),
                    ]);
                    write_packet(transport, channel, packet_type::TABULAR_RESULT, &stream).await?;
                }
            }
        }
    }

    async fn record_command(&self, auth_id: Option<&String>, command: &str) {
        let Some(auth_id) = auth_id else {
            return;
        };
        if let Err(e) = self
            .db_tx
            .send(DbMessage::RecordCommand {
                module: Module::Mssql,
                auth_id: auth_id.clone(),
                timestamp: Utc::now(),
                command: command.to_string(),
            })
            .await
        {
            log::error!("Failed to send RecordCommand to db task: {}", e);
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_auth(
        &self,
        ip: &str,
        username: &str,
        password: Option<String>,
        successful: bool,
        auth_type: &str,
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
                module: Module::Mssql,
                timestamp: Utc::now(),
                ip: ip.to_string(),
                username: username.to_string(),
                auth_type: auth_type.to_string(),
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
                    log::trace!("Recorded MSSQL auth with UUID: {}", auth_id);
                    Some(auth_id)
                }
                Ok(Err(e)) => {
                    log::error!("Database error recording MSSQL auth: {}", e);
                    None
                }
                Err(e) => {
                    log::error!("Failed to receive MSSQL auth response: {}", e);
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
                module: Module::Mssql,
                auth_id: auth_id.to_string(),
                start_time: Utc::now(),
                response_tx,
            })
            .await
        {
            Ok(_) => match response_rx.await {
                Ok(Ok(id)) => Some(id),
                Ok(Err(e)) => {
                    log::error!("Database error recording MSSQL session start: {}", e);
                    None
                }
                Err(e) => {
                    log::error!("Failed to receive MSSQL session start response: {}", e);
                    None
                }
            },
            Err(e) => {
                log::error!("Error sending MSSQL session start record: {}", e);
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
            "MSSQL session closed. Start: {}, End: {}, Duration: {}",
            start_time,
            end_time,
            duration
        );
        match self
            .db_tx
            .send(DbMessage::RecordSessionEnd {
                module: Module::Mssql,
                session_id,
                end_time,
                duration_seconds: duration.num_seconds(),
            })
            .await
        {
            Ok(_) => log::trace!("Recorded MSSQL session end"),
            Err(e) => log::error!("Error sending MSSQL session end record: {}", e),
        }
    }
}

/// Captured credential material from one authentication attempt
struct AuthCapture {
    username: String,
    /// Recovered password / token / Net-NTLMv2 hash (hashcat format)
    password: Option<String>,
    /// "password", "ntlm", "azure_ad_token", "azure_ad_password" or "sspi"
    auth_type: String,
}

/// Peeks the first byte of a plain TCP stream to detect a TLS ClientHello.
async fn peek_is_tls_client_hello(stream: &TcpStream) -> io::Result<bool> {
    let mut byte = [0u8; 1];
    loop {
        match stream.peek(&mut byte).await {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(is_tls_client_hello(byte[0])),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Same peek, on the transport wrapper (only valid while still Plain).
async fn peek_is_tls_client_hello_plain(stream: &ConnStream) -> io::Result<bool> {
    match stream {
        ConnStream::Plain(inner) => peek_is_tls_client_hello(inner).await,
        ConnStream::Tls(_) => Ok(false),
    }
}

/// Decodes a UTF-16LE payload, tolerating odd trailing bytes and garbage
fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Known RPC ProcIDs from MS-TDS 2.2.6.6 that drivers call by ID instead of
/// by name; anything unknown falls back to a synthetic name.
fn rpc_procid_name(procid: u16) -> Option<&'static str> {
    Some(match procid {
        1 => "sp_cursor",
        2 => "sp_cursoropen",
        3 => "sp_cursorprepare",
        4 => "sp_cursorexcute",
        5 => "sp_cursorprepexec",
        6 => "sp_cursorunprepare",
        7 => "sp_cursorfetch",
        8 => "sp_cursoroption",
        9 => "sp_cursorclose",
        10 => "sp_execute",
        11 => "sp_prepexec",
        12 => "sp_prepare",
        14 => "sp_unprepare",
        15 => "sp_reset_connection",
        _ => return None,
    })
}

/// Extracts a display name from an RPC request payload: either the named
/// US_VARCHAR form (ProcID == 0xFFFF) or one of the well-known ProcIDs.
fn parse_rpc_name(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return "<malformed rpc>".to_string();
    }
    let procid = u16::from_le_bytes([payload[0], payload[1]]);
    if procid != 0xFFFF {
        return match rpc_procid_name(procid) {
            Some(name) => name.to_string(),
            None => format!("sp#{procid}"),
        };
    }
    if payload.len() < 4 {
        return "<malformed rpc>".to_string();
    }
    let name_len = u16::from_le_bytes([payload[2], payload[3]]) as usize;
    let start = 4usize;
    if start + name_len > payload.len() {
        return "<malformed rpc name>".to_string();
    }
    let units: Vec<u16> = payload[start..start + name_len]
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MssqlConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Builds a minimal prelogin packet payload for the client side of the
    /// integration tests below.
    fn client_prelogin() -> Vec<u8> {
        let mut payload = vec![
            0x00, 0x00, 0x0B, 0x00, 0x06, // VERSION at 11, len 6
            0x01, 0x00, 0x11, 0x00, 0x01, // ENCRYPTION at 17, len 1
            0xFF, // terminator
        ];
        while payload.len() < 11 {
            payload.push(0);
        }
        payload.extend_from_slice(&[0xE8, 0x03, 0x00, 0x10, 0x00, 0x00]); // 16.0.1000.0
        payload.push(prelogin::encryption::ENCRYPT_OFF);
        payload
    }

    /// Builds a LOGIN7 payload for SQL authentication (same layout rules as
    /// the login7 unit tests).
    fn client_login(username: &str, password: &str) -> Vec<u8> {
        let mut data = Vec::new();
        let mut fields: Vec<(u16, u16)> = Vec::new();
        const DATA_START: usize = 36 + 8 * 4 + 6 + 4 + 4;

        let push_str = |fields: &mut Vec<(u16, u16)>, data: &mut Vec<u8>, s: &str| {
            let mut bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            bytes.push(0);
            bytes.push(0);
            fields.push(((DATA_START + data.len()) as u16, bytes.len() as u16));
            data.extend_from_slice(&bytes);
        };

        push_str(&mut fields, &mut data, "IT"); // client name
        push_str(&mut fields, &mut data, username);
        let obf: Vec<u8> = password
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .map(|b| b ^ 0xA5)
            .collect();
        fields.push(((DATA_START + data.len()) as u16, obf.len() as u16));
        data.extend_from_slice(&obf);
        push_str(&mut fields, &mut data, "sqlcmd"); // app name
        push_str(&mut fields, &mut data, "MSSQLSERVER"); // server name
        fields.push((0, 0)); // unused
        fields.push((0, 0)); // language
        push_str(&mut fields, &mut data, "master");

        let mut packet = vec![0u8; 36];
        packet[0..4].copy_from_slice(&((DATA_START + data.len()) as u32).to_le_bytes());
        packet[4..8].copy_from_slice(&0x0400_0000u32.to_le_bytes());
        packet[8..12].copy_from_slice(&8000u32.to_le_bytes());
        for (off, len) in &fields {
            packet.extend_from_slice(&off.to_le_bytes());
            packet.extend_from_slice(&len.to_le_bytes());
        }
        packet.extend_from_slice(&[0u8; 6]); // ClientID
        packet.extend_from_slice(&0u16.to_le_bytes()); // sspi offset
        packet.extend_from_slice(&0u16.to_le_bytes()); // sspi length
        packet.extend_from_slice(&0u16.to_le_bytes()); // attach db offset
        packet.extend_from_slice(&0u16.to_le_bytes()); // attach db length
        packet.extend_from_slice(&data);
        packet
    }

    fn wrap(ptype: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![ptype, 0x01];
        out.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(payload);
        out
    }

    fn test_settings(reject: bool) -> MssqlSettings {
        let mut settings = MssqlConfig::default().resolve(true);
        settings.reject_all_auth = reject;
        settings
    }

    /// Drains the DB channel the way the main database task would, replying
    /// to the oneshot channels so server sessions do not block on records.
    async fn drive_db(mut db_rx: mpsc::Receiver<DbMessage>) {
        while let Some(message) = db_rx.recv().await {
            match message {
                DbMessage::RecordAuth { response_tx, .. } => {
                    let _ = response_tx.send(Ok("00000000-0000-4000-8000-000000000001".into()));
                }
                DbMessage::RecordSessionStart { response_tx, .. } => {
                    let _ = response_tx.send(Ok("00000000-0000-4000-8000-000000000002".into()));
                }
                DbMessage::RecordConnect { .. }
                | DbMessage::RecordCommand { .. }
                | DbMessage::RecordSessionEnd { .. }
                | DbMessage::RecordFileUpload { .. }
                | DbMessage::Shutdown => {}
            }
        }
    }

    /// End-to-end plaintext session: prelogin -> LOGIN7 (SQL auth) ->
    /// LOGINACK/DONE -> SQL batch -> DONE. The DB channel receiver is
    /// dropped after buffering, so records are simply discarded.
    #[tokio::test]
    async fn plaintext_session_flow() {
        let (db_tx, db_rx) = mpsc::channel::<DbMessage>(64);
        tokio::spawn(drive_db(db_rx));
        let settings = test_settings(false);
        let server = MssqlServer::new(db_tx, settings, None, None);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { server.run_on_listener(listener).await });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&wrap(packet_type::PRELOGIN, &client_prelogin()))
            .await
            .unwrap();

        // Prelogin response must advertise ENCRYPT_OFF (TLS enabled)
        let mut header = [0u8; 8];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], packet_type::PRELOGIN);
        let len = ((header[2] as usize) << 8 | header[3] as usize) - 8;
        let mut payload = vec![0u8; len];
        client.read_exact(&mut payload).await.unwrap();
        let parsed = prelogin::parse_request(&payload);
        assert_eq!(parsed.encryption, Some(prelogin::encryption::ENCRYPT_OFF));

        // LOGIN7 with a captured credential
        client
            .write_all(&wrap(packet_type::LOGIN7, &client_login("sa", "hunter2")))
            .await
            .unwrap();

        // Response: LOGINACK + ENVCHANGE + DONE token stream
        let mut header = [0u8; 8];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], packet_type::TABULAR_RESULT);
        let len = ((header[2] as usize) << 8 | header[3] as usize) - 8;
        let mut tokens_buf = vec![0u8; len];
        client.read_exact(&mut tokens_buf).await.unwrap();
        assert_eq!(tokens_buf[0], crate::protocol::tokens::token_type::LOGINACK);
        assert!(tokens_buf.contains(&crate::protocol::tokens::token_type::DONE));

        // SQL batch round trip
        let batch: Vec<u8> = "SELECT 1"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        client
            .write_all(&wrap(packet_type::SQL_BATCH, &batch))
            .await
            .unwrap();
        let mut header = [0u8; 8];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], packet_type::TABULAR_RESULT);
        let len = ((header[2] as usize) << 8 | header[3] as usize) - 8;
        let mut done_buf = vec![0u8; len];
        client.read_exact(&mut done_buf).await.unwrap();
        assert_eq!(done_buf[0], crate::protocol::tokens::token_type::DONE);
    }

    /// With reject_all_auth the server must answer LOGIN7 with an ERROR
    /// token carrying 18456 instead of a LOGINACK.
    #[tokio::test]
    async fn reject_all_auth_flow() {
        let (db_tx, db_rx) = mpsc::channel::<DbMessage>(64);
        tokio::spawn(drive_db(db_rx));
        let settings = test_settings(true);
        let server = MssqlServer::new(db_tx, settings, None, None);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { server.run_on_listener(listener).await });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&wrap(packet_type::PRELOGIN, &client_prelogin()))
            .await
            .unwrap();
        let mut header = [0u8; 8];
        client.read_exact(&mut header).await.unwrap();
        let len = ((header[2] as usize) << 8 | header[3] as usize) - 8;
        let mut payload = vec![0u8; len];
        client.read_exact(&mut payload).await.unwrap();

        client
            .write_all(&wrap(packet_type::LOGIN7, &client_login("admin", "x")))
            .await
            .unwrap();
        let mut header = [0u8; 8];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], packet_type::TABULAR_RESULT);
        let len = ((header[2] as usize) << 8 | header[3] as usize) - 8;
        let mut payload = vec![0u8; len];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload[0], crate::protocol::tokens::token_type::ERROR);
        let number = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
        assert_eq!(number, crate::protocol::tokens::error_number::LOGIN_FAILED);
    }

    #[test]
    fn rpc_name_parsing() {
        // Named procedure: ProcID 0xFFFF + US_VARCHAR name
        let mut payload = 0xFFFFu16.to_le_bytes().to_vec();
        let name: Vec<u8> = "sp_databases"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
        payload.extend_from_slice(&name);
        assert_eq!(parse_rpc_name(&payload), "sp_databases");

        // ProcID reference
        let byid = 15u16.to_le_bytes().to_vec();
        assert_eq!(parse_rpc_name(&byid), "sp_reset_connection");

        let unknown = 99u16.to_le_bytes().to_vec();
        assert_eq!(parse_rpc_name(&unknown), "sp#99");
    }

    #[test]
    fn utf16_decode() {
        let bytes: Vec<u8> = "héllo"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode_utf16le(&bytes), "héllo");
    }
}
