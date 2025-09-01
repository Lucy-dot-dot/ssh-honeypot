use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use async_trait::async_trait;
use chrono::{DateTime, Local, Utc};
use russh::{server, Channel, ChannelId, ChannelMsg, CryptoVec, Error};
use russh::keys::{HashAlg, PublicKey};
use russh::server::{Auth, Handler, Msg, Session};
use ssh_encoding::Error as SshEncodingError;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use rand::{rng, Rng};
use rand_core::RngCore;
use crate::db::DbMessage;
use crate::shell::commands::{handle_cat_command, handle_echo_command, handle_ls_command, handle_uname_command};
use crate::shell::commands::handle_free_command;
use crate::shell::filesystem::fs2::{FileContent, FileSystem};
use crate::shell::commands::handle_ps_command;
use crate::sftp::HoneypotSftpSession;
use crate::abuseipdb::{Client as AbuseIpClient, AbuseIpError};
use crate::ipapi;

#[derive(Clone, Default)]
// Store session data
struct SessionData {
    auth_id: String,
    commands: Vec<String>,
    start_time: DateTime<Utc>,
    prompt: String,
}

// Define our SSH server handler
pub struct SshHandler {
    peer: Option<SocketAddr>,
    user: Option<String>,
    auth_id: Option<String>,
    session_data: SessionData,
    db_tx: mpsc::Sender<DbMessage>,
    current_cmd: String,
    cwd: String,
    hostname: String,
    disable_cli_interface: bool,
    authentication_banner: Option<String>,
    tarpit: bool,
    fs2: Arc<RwLock<FileSystem>>,
    /*send_task: Option<tokio::task::JoinHandle<()>>,
    send_task_tx: Option<mpsc::Sender<String>>,*/
    disable_sftp: bool,
    abuse_ip_client: Option<Arc<AbuseIpClient>>,
    reject_all_auth: bool,
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
            self.cwd = format!("/home/{}", user);
            if !self.disable_cli_interface {
                self.ensure_user_home_exists().await;
            }
            let peer_str = format!("{}", self.peer.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))).ip());

            // We'll get the actual UUID back from the database

            log::info!("Password auth attempt - Username: {}, Password: {}, IP: {}", user, password, peer_str);

            // Check IP with AbuseIPDB if client is available
            self.check_abuse_ip_db().await;

            // Record authentication attempt in database and get the UUID back
            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
            match self.db_tx.send(DbMessage::RecordAuth {
                timestamp: Utc::now(),
                ip: peer_str,
                username: user.to_string(),
                auth_type: "password".to_string(),
                password: Some(password.to_string()),
                public_key: None,
                successful: !self.reject_all_auth, // Accept/reject based on flag
                response_tx,
            }).await {
                Ok(_) => {
                    match response_rx.await {
                        Ok(Ok(auth_id)) => {
                            log::trace!("Recorded auth with UUID: {}", auth_id);
                            self.auth_id = Some(auth_id);
                        },
                        Ok(Err(e)) => {
                            log::error!("Database error recording auth: {}", e);
                        },
                        Err(e) => {
                            log::error!("Failed to receive auth response: {}", e);
                        }
                    }
                },
                Err(err) => { log::error!("Failed to send RecordAuth to db task: {}", err) },
            };

            // Simulate a small delay like a real SSH server
            let delay = rng().next_u64() % 501;
            log::trace!("Letting client wait for {}", delay);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            if self.reject_all_auth {
                log::info!("Rejected authentication attempt");
                Ok(Auth::Reject { proceed_with_methods: None, partial_success: false })
            } else {
                log::info!("Accepted new connection");
                Ok(Auth::Accept)
            }
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
            self.cwd = format!("/home/{}", user);
            if !self.disable_cli_interface {
                self.ensure_user_home_exists().await;
            }
            let key_str = format!("{}", public_key.key_data().fingerprint(HashAlg::Sha512));
            let peer_str = format!("{}", self.peer.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))).ip());

            // We'll get the actual UUID back from the database

            log::info!("Public key auth attempt - Username: {}, Key: {}, IP: {}", user, key_str, peer_str);

            // Check IP with AbuseIPDB if client is available
            self.check_abuse_ip_db().await;

            // Record authentication attempt in database and get the UUID back
            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
            match self.db_tx.send(DbMessage::RecordAuth {
                timestamp: Utc::now(),
                ip: peer_str,
                username: user.to_string(),
                auth_type: "publickey".to_string(),
                password: None,
                public_key: Some(key_str),
                successful: !self.reject_all_auth, // Accept/reject based on flag
                response_tx,
            }).await {
                Ok(_) => {
                    match response_rx.await {
                        Ok(Ok(auth_id)) => {
                            log::trace!("Recorded auth with UUID: {}", auth_id);
                            self.auth_id = Some(auth_id);
                        },
                        Ok(Err(e)) => {
                            log::error!("Database error recording auth: {}", e);
                        },
                        Err(e) => {
                            log::error!("Failed to receive auth response: {}", e);
                        }
                    }
                },
                Err(err) => { log::error!("Failed to send RecordAuth to db task: {}", err) },
            };

            // Simulate a small delay like a real SSH server
            let delay = rng().next_u64() % 501;
            log::trace!("Letting client wait for {}", delay);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

            if self.reject_all_auth {
                log::info!("Rejected authentication attempt");
                Ok(Auth::Reject { proceed_with_methods: None, partial_success: false })
            } else {
                log::info!("Accepted new connection");
                Ok(Auth::Accept)
            }
        }
    }

    fn authentication_banner(
        &mut self,
    ) -> impl Future<Output = Result<Option<String>, Self::Error>> + Send {
        async move {
            log::trace!("Displaying banner: {:?}", self.authentication_banner.as_ref());
            Ok(self.authentication_banner.clone())
        }
    }

    fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> impl Future<Output=Result<(), Self::Error>> + Send {
        async move {
            log::debug!("Channel EOF on channel: {}, closing channel", channel);
            session.close(channel)?;
            Ok(())
        }
    }

    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async move {
            if let Some(peer) = self.peer {
                log::debug!("Open session on channel: {} for ip {}", channel.id(), peer);
            } else {
                log::debug!("Open session on channel: {}", channel.id());
            }
            if let (Some(user), Some(auth_id)) = (&self.user, &self.auth_id) {
                // Initialize session data once we have a channel session
                let data = SessionData {
                    auth_id: auth_id.clone(),
                    commands: Vec::new(),
                    start_time: Utc::now(),
                    prompt: format!("{}@{}:~$ ", user, self.hostname)
                };
                self.session_data = data.clone();

                // Start the fake shell for the attacker
                let db_tx = self.db_tx.clone();
                //let (channel_reader, channel_writer) = channel.split();

                // Handle the shell session within this future
                log::trace!("Starting tokio task for shell session saving");
                tokio::spawn(async move {
                    handle_shell_session(channel, data, db_tx).await;
                });

                //let (sender_task, recv_task) = mpsc::channel::<String>(1000);
                /*self.send_task = Some(tokio::spawn(async move {
                    // TODO: Implement sending data to client from other thread
                    Self::async_data_writer(channel_writer, recv_task, tarpit).await;
                }));
                self.send_task_tx = Some(sender_task);*/

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
            if self.disable_cli_interface {
                log::debug!("Cli interface is disabled");
                session.channel_failure(channel)?;
                return Ok(())
            }

            if data[0] == 4 {
                log::debug!("Client requested closing of connection");
                match self.tarpit_data(session, channel, "\r\nlogout\r\nConnection to host closed.\r\n".as_bytes()).await {
                    Ok(_) => { log::trace!("Send closing connection text to client") },
                    Err(err) => { log::error!("Failed to send closing connection to client: {}", err) },
                };
                return Err(Error::Disconnect);
            }
            if data[0] == 127 || data[0] == 8 {
                log::trace!("Received backspace, backspacing...");
                // Well we don't want to delete prompt do we? Maybe I could send the bell code?
                // Send bell ascii code (ASCII 7) when trying to backspace on an empty command
                if self.current_cmd.is_empty() {
                    log::trace!("current cmd is empty, so why are you still backspacing?");
                    match self.tarpit_data(session, channel, &[7u8]).await {
                        Ok(_) => { log::trace!("Sent bell code to client") },
                        Err(err) => { log::error!("Failed to send bell code to client: {}", err) },
                    };
                    return Ok(());
                }

                match self.tarpit_data(session, channel, &[8u8, 32u8, 8u8]).await {
                    Ok(_) => { log::trace!("Send backspace code to client") },
                    Err(err) =>  { log::error!("Failed to send backspace code to client: {}", err) },
                };
                self.current_cmd.pop();
                return Ok(());
            }

            // CTRL+C
            if data == [3] {
                log::trace!("Received ctrl+c, clearing current command");
                self.current_cmd = String::new();
                let prompt = format!("\r\n{}", self.session_data.prompt);
                match self.tarpit_data(session, channel, prompt.as_bytes()).await {
                    Ok(_) => { log::trace!("Send prompt to client") },
                    Err(err) => { log::error!("Failed to send prompt to client: {}", err) },
                }
                return Ok(());
            }


            if let Ok(cmd) = String::from_utf8(data.to_vec()) {
                log::trace!("data: '{}' ({:?})", cmd, data);

                if cmd.ends_with("\n") || cmd.ends_with("\r") {
                    self.session_data.commands.push(self.current_cmd.clone());

                    // Record command in database
                    match self.db_tx.send(DbMessage::RecordCommand {
                        auth_id: self.session_data.auth_id.clone(),
                        timestamp: Utc::now(),
                        command: self.current_cmd.clone(),
                    }).await {
                        Ok(_) => { log::trace!("Send record command to db task") },
                        Err(err)  => { log::error!("Failed to send record command to db: {}", err) },
                    };

                    if self.current_cmd == "exit" || self.current_cmd == "logout" {
                        log::debug!("Closing session {} due to exit command", self.session_data.auth_id);
                        // Send goodbye message
                        match self.tarpit_data(session, channel, "\r\nlogout\r\nConnection to host closed.\r\n".as_bytes()).await {
                            Ok(_) => { log::trace!("Sent closing connection to client") },
                            Err(err) => { log::error!("Failed to send closing connection to client: {}", err) },
                        };
                        // Close the channel
                        return Err(Error::Disconnect);
                    }

                    // Process the command
                    let response = self.process_command().await;
                    self.current_cmd = String::new();

                    // Send the response
                    match self.tarpit_data(session, channel, "\r\n".as_bytes()).await {
                        Ok(_) => { log::trace!("Sent newline for command execution to client") },
                        Err(err) => { log::error!("Failed to send newline to client: {}", err) },
                    };
                    match self.tarpit_data(session, channel, response.as_bytes()).await {
                        Ok(_) => { log::trace!("Sent command result data to client") },
                        Err(err) => { log::error!("Failed to send command result data to client: {}", err) },
                    };
                    let prompt = format!("\r\n{} ", self.session_data.prompt);
                    match self.tarpit_data(session, channel, prompt.as_bytes()).await {
                        Ok(_) => { log::trace!("Sent prompt to client") },
                        Err(err) => { log::error!("Failed to send prompt to client after command execution: {}", err) },
                    };

                } else {
                    log::trace!("Appending to command: {}", cmd);
                    if !cmd.is_empty() {
                        self.current_cmd += &*cmd;
                        match self.tarpit_data(session, channel, cmd.as_bytes()).await {
                            Ok(_) => { log::trace!("Sent character back to client") },
                            Err(err) => { log::error!("Failed to send character back to client: {}", err) },
                        };
                    }
                }
            } else {
                log::debug!("binary data ({:?})", data);
                // Handle binary data (could be control characters)
                // Check for CTRL+D (ASCII 4) in raw data
                if data.contains(&4) {
                    // Send goodbye message and close connection
                    match self.tarpit_data(session, channel, "\r\nlogout\r\nConnection to host closed.\r\n".as_bytes()).await {
                        Ok(_) => { log::trace!("Sent logout message to client") },
                        Err(err) => { log::error!("Failed to send logout message to client: {}", err) },
                    };
                    return Err(Error::Disconnect);
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
            if self.disable_cli_interface {
                log::debug!("Cli interface is disabled");
                session.channel_failure(channel)?;
                return Ok(())
            }

            // Send a welcome message
            let welcome = format!(
                "\n\nWelcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/advantage\r\n\r\n  System information as of {}\r\n\r\n  System load:  0.08              Users logged in:        1\r\n  Usage of /:   42.6% of 30.88GB  IP address for eth0:    10.0.2.15\r\n  Memory usage: 38%               IP address for docker0:  172.17.0.1\r\n  Swap usage:   0%                \r\n  Processes:    116\r\n\r\nLast login: {} from 192.168.1.5\r\n",
                Local::now().format("%a %b %e %H:%M:%S %Y"),
                Local::now().format("%a %b %e %H:%M:%S %Y")
            );

            match self.tarpit_data(session, channel, welcome.as_bytes()).await {
                Ok(_) => { log::trace!("Send welcome message to client") },
                Err(err) => { log::error!("Failed to send welcome message to client: {}", err) },
            };

            // Send prompt
            let prompt = self.session_data.prompt.clone();
            match self.tarpit_data(session, channel, prompt.as_bytes()).await {
                Ok(_) => { log::trace!("Sent prompt to client") },
                Err(err) => { log::error!("Failed to send prompt to client: {}", err) },
            };

            Ok(())
        }
    }

    fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            log::debug!("Subsystem request: {} on channel {}", name, channel);
            
            if name == "sftp" {
                if self.disable_sftp {
                    log::info!("SFTP subsystem request denied (SFTP disabled): auth_id: {:?}", self.auth_id);
                    session.channel_failure(channel)?;
                    return Ok(());
                }

                log::info!("Starting SFTP subsystem for auth_id: {:?}", self.auth_id);
                
                if let Some(auth_id) = &self.auth_id {
                    // Create SFTP session handler
                    let _sftp_handler = HoneypotSftpSession::new(
                        self.db_tx.clone(),
                        self.fs2.clone(),
                        auth_id.clone(),
                    );

                    // Accept the subsystem request
                    session.channel_success(channel)?;
                    
                    // Run the SFTP server on this channel
                    // Note: The actual channel stream handling would need to be implemented
                    // based on the specific russh-sftp requirements
                    log::info!("SFTP subsystem started for channel {}", channel);
                    
                    // For now, just log that SFTP was requested
                    // In a complete implementation, you would need to handle the channel data
                    // and pass it to the SFTP handler
                } else {
                    log::error!("No auth_id available for SFTP session");
                    session.channel_failure(channel)?;
                }
            } else {
                log::debug!("Unsupported subsystem: {}", name);
                session.channel_failure(channel)?;
            }
            
            Ok(())
        }
    }

    /// This is ssh user@host "command", data should be UTf-8
    fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> impl Future<Output=Result<(), Self::Error>> + Send {
        async move {
            let command = String::from_utf8_lossy(data);
            // Record command in database
            match self.db_tx.send(DbMessage::RecordCommand {
                auth_id: self.session_data.auth_id.clone(),
                timestamp: Utc::now(),
                command: command.to_string(),
            }).await {
                Ok(_) => { log::trace!("Send record command to db task") },
                Err(err)  => { log::error!("Failed to send record command to db: {}", err) },
            };

            let answer = format!("You thought I'm going to execute '{}'. But jokes on you. You are now my slave.", command);
            log::debug!("Exec request received: {}", command);
            log::debug!("Answering with: {}", answer);
            self.tarpit_data(session, channel, answer.as_bytes()).await?;
            session.channel_failure(channel)?;
            Ok(())
        }
    }

}

/*impl Drop for SshHandler {
    fn drop(&mut self) {
        if let Some(send_task) = self.send_task.take() {
            send_task.abort();
        }
    }
}*/

impl SshHandler {
    // Process commands and return fake responses
    async fn process_command(&mut self) -> String {
        log::debug!("Processing command: {}", self.current_cmd);
        // First, split on pipes to handle simple command piping
        let cmd = self.current_cmd.clone();
        let mut cmd_parts = cmd.split("|");

        let primary_cmd = cmd_parts.next().unwrap_or("").trim();
        log::debug!("Identified primary cmd: {}", primary_cmd);

        // Process the primary command
        let mut output = match primary_cmd {
            cmd if cmd.starts_with("ls") => {
                let fs = self.fs2.read().await;
                handle_ls_command(cmd, &self.cwd, &fs)
            },

            "pwd" => self.cwd.clone(),

            "whoami" => "user".to_string(),

            "id" => "uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)".to_string(),

            cmd if cmd.starts_with("uname") => handle_uname_command(cmd, &*self.hostname),

            cmd if cmd.starts_with("ps") => handle_ps_command(cmd),
            
            cmd if cmd.starts_with("cat") => {
                let fs = self.fs2.read().await;
                handle_cat_command(cmd, &fs)
            },

            "wget" | "curl" => format!("{cmd}: missing URL\r\nUsage: {cmd} [OPTION]... [URL]...\r\n\r\nTry `{cmd}` --help' for more options.", cmd=cmd),

            cmd if cmd.contains("sudo") => { "Sorry, user may not run sudo on server01.".to_string() },

            cmd if cmd.starts_with("cd") => {
                let mut path = cmd.replace("cd ", "");
                if path.starts_with(".") || path.starts_with("..") {
                    let cwd = self.cwd.clone();
                    path = if cwd.ends_with("/") {
                        cwd + &path
                    } else {
                        cwd + "/" + &path
                    }
                }

                let fs = self.fs2.read().await;

                let resolved = fs.resolve_absolute_path(&path);

                match fs.follow_symlink(&resolved) {
                    Ok(entry) => {
                        match entry.file_content {
                            None => {
                                log::error!("Failed to get file content for path: {}", resolved);
                                format!("bash: cd: {}: No such file or directory", resolved)
                            }
                            Some(ref content) => {
                                match content {
                                    FileContent::Directory(_) => {
                                        self.cwd = resolved.clone();
                                        "".to_string()
                                    }
                                    FileContent::RegularFile(_) => {
                                        log::error!("Failed to cd into a regular file: {}", resolved);
                                        format!("bash: cd: {}: Not a directory", resolved)
                                    }
                                    FileContent::SymbolicLink(_) => {
                                        log::error!("Failed to resolve symbolic link to a non symbolic link. Should never happen!");
                                        format!("bash: cd: {}: Not a directory", resolved)
                                    }
                                }
                            }
                        }
                    },
                    Err(err) => {
                        log::error!("Failed to resolve path: {}", err);
                        format!("bash: cd: {}: No such file or directory", resolved)
                    }
                }

            },

            "exit" | "logout" => "".to_string(),

            "date" => Local::now().format("%a %b %e %H:%M:%S %Z %Y").to_string(),

            cmd if cmd.starts_with("free") => handle_free_command(cmd),

            cmd if cmd.starts_with("echo") => handle_echo_command(cmd),

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


    /// Handles the transmission of data over the provided session and channel, with an optional "tarpit" mode
    /// to delay the data flow intentionally.
    ///
    /// # Arguments
    ///
    /// * `session` - A mutable reference to the session through which the data is sent.
    /// * `channel` - The channel identifier where the data will be transmitted.
    /// * `data` - A byte slice representing the data to be sent.
    ///
    /// # Behavior
    ///
    /// - If the `self.tarpit` flag is set to `true`, each byte of the `data` slice is sent with an intentional delay
    ///   (between 500 to 2000 milliseconds, randomized for each byte) to simulate a slow response or tarpit mechanism.
    /// - If the `self.tarpit` flag is `false`, the entire `data` slice is sent immediately without delay.
    ///
    /// # Returns
    ///
    /// This method returns a `Result` type:
    /// - `Ok(())` if data is successfully sent.
    /// - `Err(russh::Error)` if an error occurs during data transmission.
    ///
    /// # Panics
    ///
    /// This function will panic if the random number generator (`rng()`) fails to initialize properly
    /// or if an invalid range is provided.
    ///
    ///
    /// # Notes
    ///
    /// - The tarpit mechanism is often used to slow down malicious clients or as a defensive mechanism.
    /// - The randomness of the delay is determined by a helper function `rng().random_range(500..2000)`,
    ///   which should be ensured to return consistent results within the given range.
    async fn tarpit_data(&mut self, session: &mut Session, channel: ChannelId, data: &[u8]) -> Result<(), russh::Error> {
        log::trace!("Tarpitting: {}, data len: {}", self.tarpit, data.len());
        if self.tarpit {
            for datum in data.iter() {
                let wait_time = std::time::Duration::from_millis(rng().random_range(10..700));
                log::trace!("Tarpit delay: {}", wait_time.as_millis());
                tokio::time::sleep(wait_time).await;
                session.data(channel, CryptoVec::from_slice(&[*datum]))?;
            }
        } else {
            session.data(channel, CryptoVec::from_slice(data))?;
        }
        Ok(())
    }

    async fn ensure_user_home_exists(&mut self) {
        let mut fs2 = self.fs2.write().await;
        // We don't care if the directory already exists or if it can't be created. This is a honeypot not linux
        match fs2.create_directory(&self.cwd) {
            Ok(_) => {
                log::debug!("Created user home directory: {}", self.cwd);
            },
            Err(err) => {
                log::warn!("Failed to create user home directory: {}", err);
            }
        }
    }

    async fn check_abuse_ip_db(&mut self) {
        if let Some(abuse_client) = &self.abuse_ip_client {
            if let Some(peer_addr) = self.peer {
                let ip = peer_addr.ip().to_string();
                match abuse_client.check_ip_with_cache(&ip).await {
                    Ok(response) => {
                        let score = response.data.abuse_confidence_score.unwrap_or(0);
                        let country = response.data.country_code.as_deref().unwrap_or("Unknown");
                        let is_tor = response.data.is_tor;
                        log::info!("AbuseIPDB check for {}: Confidence: {}%, Country: {}, Tor: {}, Reports: {}",
                                     ip, score, country, is_tor, response.data.total_reports);
                    },
                    Err(AbuseIpError::RateLimitExceeded(info)) => {
                        if let Some(retry_after) = info.retry_after_seconds {
                            log::warn!("AbuseIPDB daily rate limit exceeded for {}. Retry after {} seconds", ip, retry_after);
                        } else if let Some(reset_timestamp) = info.reset_timestamp {
                            let now = Utc::now().timestamp() as u64;
                            let wait_seconds = if reset_timestamp > now { reset_timestamp - now } else { 0 };
                            log::warn!("AbuseIPDB daily rate limit exceeded for {}. Resets in {} seconds", ip, wait_seconds);
                        } else {
                            log::warn!("AbuseIPDB daily rate limit exceeded for {}", ip);
                        }
                    },
                    Err(e) => {
                        log::warn!("AbuseIPDB check failed for {}: {}", ip, e);
                    }
                }
            }
        }
    }
}

// Implementation of Server trait
pub struct SshServerHandler {
    db_tx: mpsc::Sender<DbMessage>,
    disable_cli_interface: bool,
    authentication_banner: Option<String>,
    tarpit: bool,
    fs2: Arc<RwLock<FileSystem>>,
    disable_sftp: bool,
    abuse_ip_client: Option<Arc<AbuseIpClient>>,
    reject_all_auth: bool,
    ip_api_client: Option<Arc<ipapi::Client>>
}

impl server::Server for SshServerHandler {
    type Handler = SshHandler;

    // Create a new handler for each connection
    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        if let Some(peer_addr) = peer_addr {
            let ip = peer_addr.ip().to_string();
            
            // Fire-and-forget IP lookup to populate cache
            if let Some(abuse_client) = &self.abuse_ip_client {
                let client_clone = abuse_client.clone();
                let ip_clone = ip.clone();
                tokio::spawn(async move {
                    match client_clone.check_ip_with_cache(&ip_clone).await {
                        Ok(response) => {
                            log::debug!("Background AbuseIPDB lookup completed for {}", ip_clone);
                            log::debug!("{}", response.data);
                        },
                        Err(AbuseIpError::RateLimitExceeded(info)) => {
                            if let Some(retry_after) = info.retry_after_seconds {
                                log::debug!("Background AbuseIPDB lookup hit daily rate limit for {}. Retry after {} seconds", ip_clone, retry_after);
                            } else if let Some(reset_timestamp) = info.reset_timestamp {
                                let now = Utc::now().timestamp() as u64;
                                let wait_seconds = if reset_timestamp > now { reset_timestamp - now } else { 0 };
                                log::debug!("Background AbuseIPDB lookup hit daily rate limit for {}. Resets in {} seconds", ip_clone, wait_seconds);
                            } else {
                                log::debug!("Background AbuseIPDB lookup hit daily rate limit for {}", ip_clone);
                            }
                        },
                        Err(e) => {
                            log::debug!("Background AbuseIPDB lookup failed for {}: {}", ip_clone, e);
                        }
                    }
                });
            }
            
            // Check cache for additional connection info
            if let Some(abuse_client) = &self.abuse_ip_client {
                let cache = abuse_client.memory_cache.clone();
                let cache_ttl_hours = abuse_client.cache_ttl_hours;
                let ip_for_cache = ip.clone();
                let peer_for_log = peer_addr;
                
                tokio::spawn(async move {
                    let cache_read = cache.read().await;
                    if let Some(cached) = cache_read.get(&ip_for_cache) {
                        let age = Utc::now() - cached.cached_at;
                        if age < chrono::Duration::hours(cache_ttl_hours as i64) {
                            let data = &cached.response.data;
                            let country = data.country_code.as_deref().unwrap_or("Unknown");
                            let isp = data.isp.as_deref().unwrap_or("Unknown");
                            let usage_type = data.usage_type.as_deref().unwrap_or("Unknown");
                            let confidence = data.abuse_confidence_score.unwrap_or(0);
                            let is_tor = data.is_tor;
                            
                            log::info!("New connection from: {} [Country: {}, ISP: {}, Usage: {}, Confidence: {}%, Tor: {}]", 
                                     peer_for_log, country, isp, usage_type, confidence, is_tor);
                        } else {
                            log::info!("New connection from: {} (cache expired)", peer_for_log);
                        }
                    } else {
                        log::info!("New connection from: {} (no cache data)", peer_for_log);
                    }
                });
            } else {
                log::info!("New connection from: {:?}", peer_addr);
            }

            if let Some(ip_api_client) = &self.ip_api_client {
                let client = ip_api_client.clone();
                tokio::spawn(async move {
                    log::trace!("Checking IP API for {}", ip);
                    let ipinfo = match client.check_ip_with_cache(&ip).await {
                        Ok(response) => {
                            log::trace!("IP API lookup completed for {} with response: {:?}", ip, response);
                            response
                        },
                        Err(e) => {
                            log::warn!("IP API lookup failed for {}: {}", ip, e);
                            return;
                        }
                    };
                    log::info!("Additional country info for {} - Country: {}, Region: {}, lat/lon: {}/{}, org: {}", ip, ipinfo.country, ipinfo.region, ipinfo.lat, ipinfo.lon, ipinfo.org);
                });
            }

            let db_tx = self.db_tx.clone();
            tokio::spawn(async move {
                match db_tx.send(DbMessage::RecordConnect {
                    ip: peer_addr.ip().to_string(),
                    timestamp: Utc::now(),
                }).await {
                    Ok(_) => { log::trace!("Send record command to db task") },
                    Err(err)  => { log::error!("Failed to send record command to db: {}", err) },
                };
            });
        } else {
            // EBADF The argument sockfd is not a valid file descriptor.
            // EFAULT The addr argument points to memory not in a valid part of the process address space.
            // EINVAL addrlen is invalid (e.g., is negative).
            // ENOBUFS Insufficient resources were available in the system to perform the operation.
            // ENOTCONN The socket is not connected.
            // ENOTSOCK The file descriptor sockfd does not refer to a socket.

            // FIXME: using run_stream to catch the address earlier would be better but we loose a lot of lifecycle management from russh. Otherwise we could submit a patch to catch it earlier
            log::info!("New connection from unknown peer, what is this?");
        }

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
            authentication_banner: self.authentication_banner.clone(),
            tarpit: self.tarpit,
            fs2: self.fs2.clone(),
            /*send_task: None,
            send_task_tx: None,*/
            disable_sftp: self.disable_sftp,
            abuse_ip_client: self.abuse_ip_client.clone(),
            reject_all_auth: self.reject_all_auth,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {

        match error {
            Error::Disconnect => {},
            Error::IO(err) => {
                match err.kind() {
                    ErrorKind::UnexpectedEof => {
                        log::warn!("Session did not properly closed. Bad bot.");
                    }
                    ErrorKind::ConnectionReset => {
                        log::warn!("Session closed by remote peer. (TCP RST Packet)");
                    }
                    _ => {
                        log::error!("I/O Session error: {:#?}", err);
                    }
                }
            },
            Error::Elapsed(_) => {
                log::warn!("Session timed out");
            }
            Error::InactivityTimeout => {
                log::warn!("Session timed out due to inactivity");
            }
            Error::SshEncoding(err) => {
                match err {
                    SshEncodingError::Length => {
                        log::warn!("Client send invalid length packet");
                    }
                    _ => {
                        log::error!("SSH encoding error: {:#?}", err);
                    }
                }
            }
            Error::InvalidConfig(err_msg) => {
                if err_msg.contains("min_group_size") {
                    log::warn!("Client sent too low min_group_size value. Likely looking for old misconfigured embedded devices");
                } else {
                    log::error!("Invalid configuration: {}", err_msg);
                }
            }
            _ => {
                log::error!("Session error: {:#?}", error);
            }
        }
    }
}

impl SshServerHandler {
    pub fn new(db_tx: mpsc::Sender<DbMessage>, disable_cli_interface: bool, authentication_banner: Option<String>, tarpit: bool, fs2: Arc<RwLock<FileSystem>>, disable_sftp: bool, abuse_ip_client: Option<Arc<AbuseIpClient>>, reject_all_auth: bool, ip_api_client: Option<Arc<ipapi::Client>>) -> SshServerHandler {
        Self {
            disable_cli_interface,
            db_tx,
            authentication_banner,
            tarpit,
            fs2,
            disable_sftp,
            abuse_ip_client,
            reject_all_auth,
            ip_api_client
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

    log::trace!("Waiting for channel to close before saving metadata");
    // Just wait for the channel to close
    while let Some(msg) = channel.wait().await {
        log::trace!("Received channel message: {:?}", msg);
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

    log::info!("Session closed for {}. Session start {}, Session end: {}, Duration: {}", session_data.auth_id, session_data.start_time, end_time, duration);
    // Log session end to database
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    match db_tx.send(DbMessage::RecordSession {
        auth_id: session_data.auth_id,
        start_time: session_data.start_time,
        end_time,
        duration_seconds: duration.num_seconds(),
        response_tx,
    }).await {
        Ok(_) => {
            match response_rx.await {
                Ok(Ok(session_id)) => {
                    log::trace!("Successfully recorded session with ID: {}", session_id);
                },
                Ok(Err(e)) => {
                    log::error!("Database error recording session: {}", e);
                },
                Err(e) => {
                    log::error!("Failed to receive session response: {}", e);
                }
            }
        },
        Err(e) => {
            log::error!("Error sending session record: {}", e);
        }
    };
}
