mod app;
mod db;
mod shell;
mod server;

use app::App;
use db::run_db_handler;

use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::*;
use russh::server::Server as _;
use russh::*;
use std::sync::Arc;
use clap::Parser;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use crate::server::SshServerHandler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .parse_env(env_logger::Env::default())
        .filter_level(log::LevelFilter::Debug)
        .filter_module("russh", log::LevelFilter::Info)
        .init();

    let app = App::parse();

    log::info!("Current config:");
    log::info!("DB Path: {}", app.db_path.display());
    for interface in &app.interfaces {
        log::info!("Interface: {}", interface);
    }
    log::info!("Disable CLI interface: {}", app.disable_cli_interface);

    // Create a channel for database communications
    let (db_tx, db_rx) = mpsc::channel(100);

    // Start the database handler in its own thread
    let db_handle = tokio::spawn(async move {
        run_db_handler(db_rx, app.db_path).await;
    });

    // Set up the SSH server configuration
    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        server_id: SshId::Standard(String::from("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4")), // Mimic a real SSH server
        keys: vec![
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
        ],
        ..Default::default()
    };

    let config = Arc::new(config);

    log::info!("Recording authentication attempts and commands in SQLite database");

    let db_tx_clone = db_tx.clone();

    let mut tasks = Vec::new();

    for interface in app.interfaces {
        let conf = config.clone();
        let mut server_handler = SshServerHandler::new(db_tx.clone(), app.disable_cli_interface);
        tasks.push(tokio::spawn(async move {
            // Start the SSH server
            log::info!("Starting SSH honeypot on {}", interface);
            match server_handler.run_on_address(conf, interface).await {
                Ok(_) => {}
                Err(err) => {
                    log::error!("Failed to start server on interface {}: {:?}", interface, err);
                }
            };
        }))
    }

    // Ctrl+C handler for graceful shutdown
    let handle = tokio::task::spawn(async move {
        log::info!("Waiting for shutdown signal");
        #[cfg(unix)]
        {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("Failed to listen for SIGTERM");
            tokio::select! {
                _ = sig.recv() => {},
                _ = tokio::signal::ctrl_c() => {},
            }
        }
        #[cfg(windows)]
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");

        log::info!("Shutting down honeypot...");
        let _ = db_tx_clone.send(db::DbMessage::Shutdown).await;
        match db_handle.await {
            Ok(_) => {
                log::info!("Shut down honeypot db thread");
            },
            Err(e) => {
                log::error!("Failed to shutdown honeypot db: {:?}", e);
            }
        };

        tasks.into_iter().for_each(|task: JoinHandle<()>| task.abort());
    });

    match handle.await {
        Ok(_) => {},
        Err(err) => {
            log::error!("Failed to run ctrl+c listener or failed: {:?}", err);
        }
    }

    log::info!("Honeypot server shut down successfully");
    Ok(())
}