mod app;
mod db;
mod keys;
mod paths;
mod server;
mod shell;
mod sftp;
mod abuseipdb;
mod ipapi;
mod report;

use std::borrow::Cow;
use app::App;
use db::{run_db_handler, initialize_database_pool};
use std::fs::OpenOptions;

use crate::server::SshServerHandler;
use crate::abuseipdb::Client as AbuseIpClient;
use russh::server::Server as _;
use russh::*;
use shell::filesystem::fs2::FileSystem;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .parse_env(env_logger::Env::default())
        .filter_level(log::LevelFilter::Debug)
        .filter_module("russh", log::LevelFilter::Info)
        .filter_module("hyper_util", log::LevelFilter::Info)
        .filter_module("reqwest", log::LevelFilter::Info)
        .filter_module("sqlx", log::LevelFilter::Info)
        .filter_module("h2", log::LevelFilter::Info)
        .init();

    let app = match App::load() {
        Ok(app) => app,
        Err(e) => {
            log::error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    log::info!("Current config:");
    log::info!("Database URL: {}", app.database_url);
    for interface in &app.interfaces {
        log::info!("Interface: {}", interface);
    }
    log::info!("Disable CLI interface: {}", app.disable_cli_interface);
    log::info!(
        "Authentication BANNER: {}",
        app.authentication_banner.clone().unwrap_or_default()
    );
    log::info!("AbuseIPDB cache cleanup interval: {} hours", app.abuse_ip_cache_cleanup_interval_hours);

    log::trace!("Generating or loading keys");
    let keys = keys::load_or_generate_keys(&app);

    // Initialize PostgreSQL connection pool
    let pool = match initialize_database_pool(&app.database_url, false).await {
        Ok(pool) => pool,
        Err(e) => {
            log::error!("Failed to initialize database pool: {}", e);
            std::process::exit(1);
        }
    };

    // Create a channel for database communications
    let (db_tx, db_rx) = mpsc::channel(100);

    // Start the database handler in its own thread  
    let pool_for_db_handler = pool.clone();
    let db_handle = tokio::spawn(async move {
        run_db_handler(db_rx, pool_for_db_handler).await;
    });

    log::trace!("Creating server config");

    // Set up the SSH server configuration
    let config = russh::server::Config {
        keepalive_max: 5,
        keepalive_interval: Some(std::time::Duration::from_secs(20)),
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        server_id: SshId::Standard(app.server_id.clone()),
        keys: vec![keys.ed25519, keys.rsa, keys.ecdsa],
        methods: (&[MethodKind::PublicKey, MethodKind::Password, MethodKind::KeyboardInteractive]).as_slice().into(),
        preferred: Preferred {
            kex: Cow::Borrowed(&[
                // russh::negotiation::SAFE_KEX_ORDER
                kex::MLKEM768X25519_SHA256,
                kex::CURVE25519,
                kex::CURVE25519_PRE_RFC_8731,
                kex::DH_GEX_SHA256,
                kex::DH_G18_SHA512,
                kex::DH_G17_SHA512,
                kex::DH_G16_SHA512,
                kex::DH_G15_SHA512,
                kex::DH_G14_SHA256,
                kex::EXTENSION_SUPPORT_AS_CLIENT,
                kex::EXTENSION_SUPPORT_AS_SERVER,
                kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                // Old bad insecure cipher
                kex::DH_G1_SHA1,
                kex::DH_G14_SHA1,
                kex::DH_GEX_SHA1,
            ]),
            key: Default::default(),
            cipher: Default::default(),
            mac: Default::default(),
            compression: Default::default(),
        },
        ..Default::default()
    };
    log::trace!("Finished generating keys");

    let config = Arc::new(config);

    log::info!("Recording authentication attempts and commands in database");

    let db_tx_clone = db_tx.clone();

    let mut tasks = Vec::with_capacity(app.interfaces.len());

    log::trace!("Creating filesystem");
    let fs2 = Arc::new(RwLock::new(FileSystem::default()));

    // Create AbuseIPDB client if API key is provided
    let abuse_ip_client = if let Some(api_key) = &app.abuse_ip_db_api_key {
        log::info!("AbuseIPDB integration enabled");
        Some(Arc::new(AbuseIpClient::new(api_key.clone(), pool.clone(), None)))
    } else {
        log::info!("AbuseIPDB integration disabled (no API key provided)");
        None
    };

    let ip_api_client = if app.disable_ipapi {
        None
    } else {
        Some(Arc::new(ipapi::Client::new(pool.clone(), None)))
    };

    // Start background cache cleanup task
    let pool_cleanup = pool.clone();
    let cleanup_interval_hours = app.abuse_ip_cache_cleanup_interval_hours;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(cleanup_interval_hours as u64 * 3600));
        log::info!("Starting AbuseIPDB cache cleanup task (interval: {} hours)", cleanup_interval_hours);
        
        loop {
            interval.tick().await;
            
            match sqlx::query(
                "DELETE FROM abuse_ip_cache WHERE timestamp < NOW() - INTERVAL '24 hours'"
            ).execute(&pool_cleanup).await {
                Ok(result) => {
                    let rows_deleted = result.rows_affected();
                    if rows_deleted > 0 {
                        log::info!("Cleaned up {} expired AbuseIPDB cache entries", rows_deleted);
                    } else {
                        log::debug!("No expired AbuseIPDB cache entries to clean up");
                    }
                },
                Err(e) => {
                    log::error!("Failed to cleanup expired AbuseIPDB cache entries: {}", e);
                }
            }
        }
    });

    if !app.disable_base_tar_gz_loading {
        if app.disable_cli_interface {
            log::warn!(
                "Loading base.tar.gz is useless when the command line interface is disabled. It is recommended to disable it with -g/--disable-base-tar-gz-loading. Sleeping for 5 seconds to let you cancel loading"
            );
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        log::trace!("Reading base.tar.gz and processing it");

        match OpenOptions::new()
            .create(false)
            .write(false)
            .read(true)
            .open(app.base_tar_gz_path.clone())
        {
            Ok(file) => {
                match file.metadata() {
                    Ok(meta) => {
                        log::debug!("File size: {}", meta.len());
                    }
                    Err(err) => {
                        log::error!(
                            "Failed to get metadata for {}: {:?}",
                            app.base_tar_gz_path.display(),
                            err
                        );
                    }
                }
                log::trace!("Opened {}", app.base_tar_gz_path.display());
                match fs2.write().await.process_targz(file) {
                    Ok(_) => {
                        log::debug!("Processed {} successfully", app.base_tar_gz_path.display());
                    }
                    Err(err) => {
                        log::error!(
                            "Failed to process {}: {:?}. Continuing anyway",
                            app.base_tar_gz_path.display(),
                            err
                        );
                    }
                }
            }
            Err(err) => {
                log::error!("Failed to open base.tar.gz: {:?}. Continuing anyway", err);
            }
        }
    }

    for interface in app.interfaces {
        let conf = config.clone();

        let mut server_handler = SshServerHandler::new(
            db_tx.clone(),
            app.disable_cli_interface,
            app.authentication_banner.clone(),
            app.tarpit,
            fs2.clone(),
            app.enable_sftp,
            abuse_ip_client.clone(),
            app.reject_all_auth,
            ip_api_client.clone(),
            app.welcome_message.clone(),
            app.hostname.clone()
        );
        tasks.push(tokio::spawn(async move {
            // Start the SSH server
            log::info!("Starting SSH honeypot on {}", interface);
            let socket = match create_socket_with_reuse(interface, app.disable_so_reuseaddr, app.disable_so_reuseport) {
                Ok(socket) => socket,
                Err(err) => {
                    log::error!(
                        "Failed to create socket on interface {}: {:?}",
                        interface,
                        err
                    );
                    return;
                }
            };

            match server_handler.run_on_socket(conf, &socket).await {
                Ok(_) => {}
                Err(err) => {
                    log::error!(
                        "Failed to start server on interface {}: {:?}",
                        interface,
                        err
                    );
                }
            };
        }))
    }

    // Ctrl+C handler for graceful shutdown
    let handle = tokio::task::spawn(async move {
        log::info!("Waiting for shutdown signal");
        #[cfg(unix)]
        {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to listen for SIGTERM");
            tokio::select! {
                _ = sig.recv() => {},
                _ = tokio::signal::ctrl_c() => {},
            }
        }
        #[cfg(windows)]
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl+c");

        log::info!("Shutting down honeypot...");
        let _ = db_tx_clone.send(db::DbMessage::Shutdown).await;
        match db_handle.await {
            Ok(_) => {
                log::info!("Shut down honeypot db thread");
            }
            Err(e) => {
                log::error!("Failed to shutdown honeypot db: {:?}", e);
            }
        };

        tasks
            .into_iter()
            .for_each(|task: JoinHandle<()>| task.abort());
    });

    match handle.await {
        Ok(_) => {}
        Err(err) => {
            log::error!("Failed to run ctrl+c listener or failed: {:?}", err);
        }
    }

    log::info!("Honeypot server shut down successfully");
    Ok(())
}

/// Helper function to create a socket with SO_REUSEPORT and SO_REUSEADDR.
///
/// Linux has an interesting implementation for net.ipv6.bindv6only = 0
/// Where if you already listen on a port on IPv4 and then bind to the same port using IPv6,
/// binding will fail due to conflicting ports.
/// Linux wants to be helpful and allow IPv4 clients to connect to an IPv6 socket. But if something already listens...
#[allow(unused_variables)]
fn create_socket_with_reuse(addr: SocketAddr, disable_reuse_addr: bool, disable_reuse_port: bool) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(!disable_reuse_addr)?;

    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket.set_reuseport(!disable_reuse_port)?;

    socket.bind(addr)?;
    socket.listen(1024)
}
