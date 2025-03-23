mod cat;
mod filesystem;
mod app;
mod db;

use cat::get_fake_file_content;
use app::App;
use db::run_db_handler;

use std::net::SocketAddr;
use async_trait::async_trait;
use chrono::prelude::*;
use futures::Future;
use russh::keys::ssh_key::rand_core::{OsRng, RngCore};
use russh::keys::*;
use russh::server::{Auth, Handler, Session, Msg};
use russh::Channel;
use russh::server::Server as _;
use russh::*;
use std::sync::Arc;
use clap::Parser;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uuid::Uuid;

// Database message types
#[derive(Debug)]
enum DbMessage {
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

#[derive(Clone, Default)]
// Store session data
struct SessionData {
    auth_id: String,
    user: String,
    commands: Vec<String>,
    start_time: DateTime<Utc>,
}

// Define our SSH server handler
struct SshHandler {
    peer: Option<SocketAddr>,
    user: Option<String>,
    auth_id: Option<String>,
    session_data: SessionData,
    db_tx: mpsc::Sender<DbMessage>,
    current_cmd: String,
    cwd: String,
    hostname: String,
    disable_cli_interface: bool,
}

// Implementation of the Handler trait for our SSH server
#[async_trait]
impl Handler for SshHandler {
    type Error = russh::Error;

    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            self.user = Some(user.to_string());
            let peer_str = format!("{}", self.peer.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))));

            // Generate a UUID for this auth attempt
            let auth_id = Uuid::new_v4().to_string();
            self.auth_id = Some(auth_id.clone());

            log::info!("Password auth attempt - Username: {}, Password: {}, IP: {}", user, password, peer_str);

            // Record authentication attempt in database
            let _ = self.db_tx.send(DbMessage::RecordAuth {
                id: auth_id,
                timestamp: Utc::now(),
                ip: peer_str,
                username: user.to_string(),
                auth_type: "password".to_string(),
                password: Some(password.to_string()),
                public_key: None,
                successful: true, // We're accepting all auth in honeypot
            }).await;

            // Simulate a small delay like a real SSH server
            let delay = OsRng::default().next_u64() % 501;
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

            if self.disable_cli_interface {
                log::info!("Cli interface is disabled");
                return Ok(Auth::reject())
            }
            log::info!("Accepted new connection");
            // For honeypot, we accept all auth attempts
            Ok(Auth::Accept)
        }
    }

    // Handle public key authentication
    fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            self.user = Some(user.to_string());
            let user_str = user.to_string();
            let key_str = format!("{}", public_key.key_data().fingerprint(HashAlg::Sha512));
            let peer_str = format!("{}", self.peer.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))));

            // Generate a UUID for this auth attempt
            let auth_id = Uuid::new_v4().to_string();
            self.auth_id = Some(auth_id.clone());

            log::info!("Public key auth attempt - Username: {}, Key: {}, IP: {}", user_str, key_str, peer_str);

            // Record authentication attempt in database
            let _ = self.db_tx.send(DbMessage::RecordAuth {
                id: auth_id,
                timestamp: Utc::now(),
                ip: peer_str,
                username: user_str,
                auth_type: "publickey".to_string(),
                password: None,
                public_key: Some(key_str),
                successful: true, // We're accepting all auth in honeypot
            }).await;

            // Simulate a small delay like a real SSH server
            let delay = OsRng::default().next_u64() % 501;
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

            if self.disable_cli_interface {
                log::debug!("Cli interface is disabled");
                return Ok(Auth::reject())
            }
            log::info!("Accepted new connection");
            // For honeypot, we accept all auth attempts
            Ok(Auth::Accept)
        }
    }

    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async move {
            log::debug!("Open session on channel: {}", channel.id());
            if let (Some(user), Some(auth_id)) = (&self.user, &self.auth_id) {
                // Initialize session data once we have a channel session
                let data = SessionData {
                    auth_id: auth_id.clone(),
                    user: user.clone(),
                    commands: Vec::new(),
                    start_time: Utc::now(),
                };
                self.session_data = data.clone();

                // Start the fake shell for the attacker
                let db_tx = self.db_tx.clone();
                // Handle the shell session within this future
                tokio::spawn(async move {
                    handle_shell_session(channel, data, db_tx).await;
                });
            }

            Ok(true)
        }
    }

    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            if data[0] == 4 {
                let _ = session.data(channel, CryptoVec::from("\r\nlogout\r\nConnection to host closed.\r\n".as_bytes()));
                return Err(russh::Error::Disconnect);
            }
            if data[0] == 127 || data[0] == 8 {
                log::trace!("Received backspace, backspacing...");
                // Well we don't want to delete prompt do we? Maybe I could send the bell code?
                // TODO: Send bell ascii code
                if self.current_cmd.is_empty() {
                    return Ok(());
                }

                let _ = session.data(channel, CryptoVec::from_slice(&[8u8, 32u8, 8u8]));
                self.current_cmd.pop();
                return Ok(());
            }

            // CTRL+C
            if data == [3] {
                log::trace!("Received ctrl+c, clearing current command");
                self.current_cmd = String::new();
                let prompt = format!("\r\n{}@{}:~$ ", self.session_data.user, self.hostname);
                let _ = session.data(channel, CryptoVec::from(prompt.as_bytes()));
                return Ok(());
            }


            if let Ok(cmd) = String::from_utf8(data.to_vec()) {
                log::trace!("data: '{}' ({:?})", cmd, data);

                if cmd.ends_with("\n") || cmd.ends_with("\r") {
                    self.session_data.commands.push(self.current_cmd.clone());

                    // Record command in database
                    let _ = self.db_tx.send(DbMessage::RecordCommand {
                        id: Uuid::new_v4().to_string(),
                        auth_id: self.session_data.auth_id.clone(),
                        timestamp: Utc::now(),
                        command: self.current_cmd.clone(),
                    }).await;

                    if self.current_cmd == "exit" || self.current_cmd == "logout" {
                        log::debug!("Closing session {} due to exit command", self.session_data.auth_id);
                        // Send goodbye message
                        let _ = session.data(channel, CryptoVec::from("\r\nlogout\r\nConnection to host closed.\r\n".as_bytes()));
                        // Close the channel
                        return Err(russh::Error::Disconnect);
                    }

                    // Process the command
                    let response = self.process_command();
                    self.current_cmd = String::new();

                    // Send the response
                    let _ = session.data(channel, CryptoVec::from("\r\n".as_bytes()));
                    let _ = session.data(channel, CryptoVec::from(response.as_bytes()));
                    let prompt = format!("\r\n{}@{}:~$ ", self.session_data.user, self.hostname);
                    let _ = session.data(channel, CryptoVec::from(prompt.as_bytes()));

                } else {
                    log::trace!("Appending to command: {}", cmd);
                    if !cmd.is_empty() {
                        self.current_cmd += &*cmd;
                        let _ = session.data(channel, CryptoVec::from(cmd.as_bytes()));
                    }
                }
            } else {
                log::debug!("binary data ({:?})", data);
                // Handle binary data (could be control characters)
                // Check for CTRL+D (ASCII 4) in raw data
                if data.contains(&4) {
                    // Send goodbye message and close connection
                    let _ = session.data(channel, CryptoVec::from("\r\nlogout\r\nConnection to host closed.\r\n".as_bytes()));
                    return Err(russh::Error::Disconnect);
                }
            }
            Ok(())
        }
    }

    fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            log::debug!("Getting shell command request for channel: {}", channel);
            // Send a welcome message
            let welcome = format!(
                "\n\nWelcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/advantage\r\n\r\n  System information as of {}\r\n\r\n  System load:  0.08              Users logged in:        1\r\n  Usage of /:   42.6% of 30.88GB  IP address for eth0:    10.0.2.15\r\n  Memory usage: 38%               IP address for docker0:  172.17.0.1\r\n  Swap usage:   0%                \r\n  Processes:    116\r\n\r\nLast login: {} from 192.168.1.5\r\n",
                Local::now().format("%a %b %e %H:%M:%S %Y"),
                Local::now().format("%a %b %e %H:%M:%S %Y")
            );

            let _ = session.data(channel, CryptoVec::from(welcome.as_bytes()));

            // Send prompt
            let prompt = format!("{}@{}:~$ ", self.session_data.user, self.hostname);
            let _ = session.data(channel, CryptoVec::from(prompt.as_bytes()));

            Ok(())
        }
    }
}

impl SshHandler {
    // Process commands and return fake responses
    fn process_command(&mut self) -> String {
        log::debug!("Processing command: {}", self.current_cmd);
        // First, split on pipes to handle simple command piping
        let cmd = self.current_cmd.clone();
        let mut cmd_parts = cmd.split("|");

        let primary_cmd = cmd_parts.next().unwrap_or("").trim();
        log::debug!("Identified primary cmd: {}", primary_cmd);

        // Process the primary command
        let mut output = match primary_cmd {
            cmd if cmd.starts_with("ls") =>
                filesystem::handle_ls_command(cmd, &*self.cwd),

            "pwd" => self.cwd.clone(),

            "whoami" => "user".to_string(),

            "id" => "uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)".to_string(),

            "uname" => "Linux server01 5.4.0-109-generic #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux".to_string(),

            "ps" => "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\nroot         1  0.0  0.0 168940  9488 ?        Ss   Jun10   0:01 /sbin/init\r\nroot         2  0.0  0.0      0     0 ?        S    Jun10   0:00 [kthreadd]\r\nroot        10  0.0  0.0      0     0 ?        I<   Jun10   0:00 [rcu_tasks_kthr]\r\nuser      1820  0.0  0.0  17672  3396 pts/0    R+   12:34   0:00 ps aux\r\n".to_string(),

            cmd if cmd.starts_with("cat ") => {
                let file_path = cmd[4..].trim();
                match get_fake_file_content(file_path) {
                    Some(content) => content,
                    None => format!("cat: {}: No such file or directory\n", file_path)
                }
            },

            "wget" | "curl" => format!("{cmd}: missing URL\r\nUsage: {cmd} [OPTION]... [URL]...\r\n\r\nTry `{cmd}` --help' for more options.", cmd=cmd),

            "sudo" => if cmd.contains("-l") { "Sorry, user user may not run sudo on server01.".to_string() } else { "".to_string() },

            "cd" => "".to_string(),

            "exit" | "logout" => "".to_string(),

            "date" => Local::now().format("%a %b %e %H:%M:%S %Z %Y").to_string(),

            "free" => "              total        used        free      shared  buff/cache   available\r\nMem:           3953        1499        1427         272        1027        1903\r\nSwap:          2048           0        2048".to_string(),

            "echo" => "".to_string(),
            cmd if cmd.starts_with("echo ") => cmd[5..].to_string() + "\r\n",

            _ => format!("bash: {}: command not found\r\n", primary_cmd),
        };

        for piped_cmd in cmd_parts {
            if piped_cmd.trim().starts_with("grep ") {
                let grep_term = piped_cmd.trim()[5..].trim();
                // Very simple grep implementation
                output = output.lines()
                    .filter(|line| line.contains(grep_term))
                    .collect::<Vec<&str>>()
                    .join("\n") + "\n";
            }
        }

        output
    }
}

// Implementation of Server trait
struct SshServerHandler {
    db_tx: mpsc::Sender<DbMessage>,
    disable_cli_interface: bool,
}

impl server::Server for SshServerHandler {
    type Handler = SshHandler;

    // Create a new handler for each connection
    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        log::info!("New connection from: {:?}", peer_addr);

        SshHandler {
            peer: peer_addr,
            user: None,
            auth_id: None,
            session_data: SessionData::default(),
            db_tx: self.db_tx.clone(),
            current_cmd: String::new(),
            cwd: String::from("/home/user"),
            hostname: "server01".to_string(),
            disable_cli_interface: self.disable_cli_interface,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        match error {
            <Self::Handler as Handler>::Error::Disconnect => {}
            _ => {
                log::error!("Session error: {:#?}", error);
            }
        }
    }
}

// Function to handle the fake shell session
async fn handle_shell_session(
    mut channel: Channel<Msg>,
    session_data: SessionData,
    db_tx: mpsc::Sender<DbMessage>,
) {
    // We don't need to do anything specific here since
    // commands are handled in the data/shell_request/exec_request methods

    // Just wait for the channel to close
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Close => {
                break;
            }
            ChannelMsg::Failure => {
                break;
            }
            ChannelMsg::OpenFailure(_) => {
                break;
            }
            _ => {}
        }
    }

    // Record the end of the session
    let end_time = Utc::now();
    let duration = end_time - session_data.start_time;

    // Log session end to database
    match db_tx.send(DbMessage::RecordSession {
        auth_id: session_data.auth_id,
        start_time: session_data.start_time,
        end_time,
        duration_seconds: duration.num_seconds(),
    }).await {
        Ok(_) => {
            log::trace!("Successfully recorded session");
        },
        Err(e) => {
            log::error!("Error sending session record: {}", e);
        }
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .parse_env(env_logger::Env::default())
        .filter_level(log::LevelFilter::Debug)
        .filter_module("russh", log::LevelFilter::Info)
        .init();

    let app = App::parse();

    // Create a channel for database communications
    let (db_tx, db_rx) = mpsc::channel(100);

    // Start the database handler in its own thread
    let db_handle = tokio::spawn(async move {
        run_db_handler(db_rx, app.db_path).await;
    });

    // Set up the SSH server configuration
    let config = server::Config {
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
        let mut server_handler = SshServerHandler {
            db_tx: db_tx.clone(),
            disable_cli_interface: app.disable_cli_interface,
        };
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
        let _ = db_tx_clone.send(DbMessage::Shutdown).await;
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