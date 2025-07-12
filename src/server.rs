use std::net::SocketAddr;
use std::sync::Arc;
use async_trait::async_trait;
use chrono::{DateTime, Local, Utc};
use russh::{server, Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, CryptoVec, Error};
use russh::keys::{HashAlg, PublicKey};
use russh::server::{Auth, Handler, Msg, Session};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use uuid::Uuid;
use rand::{rng, Rng};
use rand_core::RngCore;
use crate::db::DbMessage;
use crate::shell::commands::{handle_cat_command, handle_echo_command, handle_ls_command, handle_uname_command};
use crate::shell::commands::handle_free_command;
use crate::shell::filesystem::fs2::{FileContent, FileSystem};
use crate::shell::commands::handle_ps_command;

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
    send_task: Option<tokio::task::JoinHandle<()>>,
    send_task_tx: Option<mpsc::Sender<String>>,
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
            self.ensure_user_home_exists().await;
            let peer_str = format!("{}", self.peer.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))));

            // Generate a UUID for this auth attempt
            let auth_id = Uuid::new_v4().to_string();
            self.auth_id = Some(auth_id.clone());

            log::info!("Password auth attempt - Username: {}, Password: {}, IP: {}", user, password, peer_str);

            // Record authentication attempt in database
            match self.db_tx.send(DbMessage::RecordAuth {
                id: auth_id,
                timestamp: Utc::now(),
                ip: peer_str,
                username: user.to_string(),
                auth_type: "password".to_string(),
                password: Some(password.to_string()),
                public_key: None,
                successful: true, // We're accepting all auth in honeypot
            }).await {
                Ok(_) => { log::trace!("Send RecordAuth to db task") },
                Err(err) => { log::error!("Failed to send RecordAuth to db task: {}", err) },
            };

            // Simulate a small delay like a real SSH server
            let delay = rng().next_u64() % 501;
            log::trace!("Letting client wait for {}", delay);
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
            self.cwd = format!("/home/{}", user);
            self.ensure_user_home_exists().await;
            let key_str = format!("{}", public_key.key_data().fingerprint(HashAlg::Sha512));
            let peer_str = format!("{}", self.peer.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))));

            // Generate a UUID for this auth attempt
            let auth_id = Uuid::new_v4().to_string();
            self.auth_id = Some(auth_id.clone());

            log::info!("Public key auth attempt - Username: {}, Key: {}, IP: {}", user, key_str, peer_str);

            // Record authentication attempt in database
            match self.db_tx.send(DbMessage::RecordAuth {
                id: auth_id,
                timestamp: Utc::now(),
                ip: peer_str,
                username: user.to_string(),
                auth_type: "publickey".to_string(),
                password: None,
                public_key: Some(key_str),
                successful: true, // We're accepting all auth in honeypot
            }).await {
                Ok(_) => { log::trace!("Send RecordAuth to db task") },
                Err(err) => { log::error!("Failed to send RecordAuth to db task: {}", err) },
            };

            // Simulate a small delay like a real SSH server
            let delay = rng().next_u64() % 501;
            log::trace!("Letting client wait for {}", delay);
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

    fn authentication_banner(
        &mut self,
    ) -> impl Future<Output = Result<Option<String>, Self::Error>> + Send {
        async move {
            log::trace!("Displaying banner: {:?}", self.authentication_banner.as_ref());
            Ok(self.authentication_banner.clone())
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
                    commands: Vec::new(),
                    start_time: Utc::now(),
                    prompt: format!("{}@{}:~$ ", user, self.hostname)
                };
                self.session_data = data.clone();

                // Start the fake shell for the attacker
                let db_tx = self.db_tx.clone();
                let (channel_reader, channel_writer) = channel.split();

                // Handle the shell session within this future
                log::trace!("Starting tokio task for shell session saving");
                tokio::spawn(async move {
                    handle_shell_session(channel_reader, data, db_tx).await;
                });

                let (sender_task, recv_task) = mpsc::channel::<String>(1000);
                let tarpit = self.tarpit;
                self.send_task = Some(tokio::spawn(async move {
                    // TODO: Implement sending data to client from other thread
                    Self::async_data_writer(channel_writer, recv_task, tarpit).await;
                }));
                self.send_task_tx = Some(sender_task);

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
                        id: Uuid::new_v4().to_string(),
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

}

impl Drop for SshHandler {
    fn drop(&mut self) {
        if let Some(send_task) = self.send_task.take() {
            send_task.abort();
        }
    }
}

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

    /// Asynchronously writes data from a receiver to a channel writer, with optional tarpit-induced delay.
    ///
    /// # Parameters
    ///
    /// - `channel_writer`: A [`ChannelWriteHalf<Msg>`] instance used to send data to a client over a channel.
    /// - `recv_task`: An [`Receiver<String>`] that supplies messages (in string format) to be sent asynchronously.
    /// - `tarpit`: A boolean indicating whether to introduce a "tarpit" behavior, which adds random delays between sending each byte of the data.
    ///
    /// # Behavior
    ///
    /// This function runs an infinite loop that waits for incoming data from the `recv_task` receiver. When data is available:
    ///
    /// - If `tarpit` is `true`, the function introduces random delays (between 10 milliseconds and 700 milliseconds) before sending each byte of the data individually to the client.
    /// - If `tarpit` is `false`, the full data buffer is sent to the client in one go.
    ///
    /// The function uses the `channel_writer` to send data to the client and logs the progress:
    ///
    /// - If the data is successfully sent, a debug-level log is recorded.
    /// - If there is an error while sending data, it logs an error and exits the loop.
    ///
    /// If `recv_task.recv()` returns `None`, an error is logged (indicating that the task has been closed) and the loop breaks.
    ///
    /// The `tarpit` behavior is particularly useful for simulating delayed or throttled transmission of data.
    ///
    /// # Logging
    ///
    /// - Uses `log::trace!` to provide detailed trace-level logs for debugging purposes.
    /// - Uses `log::error!` to record and highlight errors during the execution.
    ///
    /// # Errors
    ///
    /// - Logs an error if sending data to the client fails.
    /// - Logs an error if the `recv_task` channel unexpectedly closes.
    ///
    /// # Dependencies
    ///
    /// - [`tokio`] for asynchronous execution and `sleep` functionality.
    /// - [`log`] for structured application logging.
    /// - [`rng()`] to generate random delay durations when `tarpit` is enabled.
    ///
    /// # Example
    ///
    /// ```rust
    /// let (writer, receiver) = create_channel(); // Hypothetical channel creation
    /// let recv_task: Receiver<String> = create_recv_task();
    /// async_data_writer(writer, recv_task, true).await;
    /// ```
    async fn async_data_writer(channel_writer: ChannelWriteHalf<Msg>, mut recv_task: mpsc::Receiver<String>, tarpit: bool) {
        loop {
            match recv_task.recv().await {
                Some(data) => {
                    log::trace!("Sending data to client: {}", data);
                    let data = data.as_bytes();
                    if tarpit {
                        for datum in data.iter() {
                            let wait_time = std::time::Duration::from_millis(rng().random_range(10..700));
                            log::trace!("Tarpit delay: {}", wait_time.as_millis());
                            tokio::time::sleep(wait_time).await;
                            let data: &[u8] = &[*datum];
                            match channel_writer.data(data).await {
                                Ok(_) => { log::trace!("Sent data to client") },
                                Err(err) => {
                                    log::error!("Failed to send data to client: {}", err);
                                    break;
                                },
                            };
                        }
                    } else {
                        match channel_writer.data(data).await {
                            Ok(_) => { log::trace!("Sent data in full to client") },
                            Err(err) => {
                                log::error!("Failed to send data to client: {}", err);
                                break;
                            },
                        }
                    }
                },
                None => {
                    log::error!("Send task received None from channel");
                    break;
                },
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
            authentication_banner: self.authentication_banner.clone(),
            tarpit: self.tarpit,
            fs2: self.fs2.clone(),
            send_task: None,
            send_task_tx: None
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

impl SshServerHandler {
    pub fn new(db_tx: mpsc::Sender<DbMessage>, disable_cli_interface: bool, authentication_banner: Option<String>, tarpit: bool, fs2: Arc<RwLock<FileSystem>>) -> SshServerHandler {
        Self {
            disable_cli_interface,
            db_tx,
            authentication_banner,
            tarpit,
            fs2,
        }
    }
}

// Function to handle the fake shell session
async fn handle_shell_session(
    mut channel: ChannelReadHalf,
    session_data: SessionData,
    db_tx: mpsc::Sender<DbMessage>,
) {
    // We don't need to do anything specific here since
    // commands are handled in the data/shell_request/exec_request methods

    log::trace!("Waiting for channel to close before saving metadata");
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

    log::info!("Session closed for {}. Session start {}, Session end: {}, Duration: {}", session_data.auth_id, session_data.start_time, end_time, duration);
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
