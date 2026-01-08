use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};
use crate::paths::PathManager;

// Default interfaces
const DEFAULT_INTERFACES: [SocketAddr; 2] = [
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 2222),
    SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 2222),
];

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub interfaces: Option<Vec<String>>, // Store as strings for TOML compatibility
    pub database_url: Option<String>,
    pub disable_cli_interface: Option<bool>,
    pub authentication_banner: Option<String>,
    pub tarpit: Option<bool>,
    pub disable_base_tar_gz_loading: Option<bool>,
    pub base_tar_gz_path: Option<String>,
    pub key_folder: Option<String>,
    pub disable_so_reuseport: Option<bool>,
    pub disable_so_reuseaddr: Option<bool>,
    pub enable_sftp: Option<bool>,
    pub abuse_ip_db_api_key: Option<String>,
    pub abuse_ip_cache_cleanup_interval_hours: Option<u32>,
    pub reject_all_auth: Option<bool>,
    pub disable_ipapi: Option<bool>,
    pub server_id: Option<String>,
    pub welcome_message: Option<String>,
    pub hostname: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interfaces: None,
            database_url: None,
            disable_cli_interface: None,
            authentication_banner: None,
            tarpit: None,
            disable_base_tar_gz_loading: None,
            base_tar_gz_path: None,
            key_folder: None,
            disable_so_reuseport: None,
            disable_so_reuseaddr: None,
            enable_sftp: None,
            abuse_ip_db_api_key: None,
            abuse_ip_cache_cleanup_interval_hours: None,
            reject_all_auth: None,
            disable_ipapi: None,
            server_id: None,
            welcome_message: None,
            hostname: None,
        }
    }
}

#[derive(clap::Parser, Debug)]
#[command(version, about = "A small ssh server that allows for advanced honeypot usage", long_about = "A small ssh server that allows for advanced honeypot usage. It provides a fake command interface mimicking ubuntu without any fear of malicious code execution, since no commands are actually executed. It also records all commands in a central database")]
pub struct CliArgs {
    /// Path to configuration file
    #[arg(short = 'f', long = "config", env = "CONFIG_FILE")]
    pub config_file: Option<PathBuf>,
    /// The port to listen on, requires to be over 1000 or use linux setcap cap_net_bind_service command
    #[arg(short = 'i', long = "interface", env = "INTERFACE")]
    pub interfaces: Option<Vec<SocketAddr>>,

    /// PostgreSQL database connection URL
    #[arg(short = 'd', long = "database-url", env = "DATABASE_URL")]
    pub database_url: Option<String>,

    /// Disable the fake cli interface provided and only save passwords and/or key authentication attempts. Does not reject the authentication, --reject-all-auth can be used to do that
    #[arg(short = 'c', long = "disable-cli-interface", env = "DISABLE_CLI_INTERFACE", action = ArgAction::SetTrue)]
    pub disable_cli_interface: bool,
    
    /// Authentication banner to show. Can make the server more realistic
    #[arg(short, long, env = "AUTHENTICATION_BANNER")]
    pub authentication_banner: Option<String>,

    /// Makes the response veryyyyy slooooooooooowww in order to slow down attackers and "tarpit" them
    #[arg(short, long, env = "TARPIT", action = ArgAction::SetTrue)]
    pub tarpit: bool,

    /// Disables the base tar.gz loading, which is used to load the base system
    #[arg(short = 'g', long = "disable-base-tar-gz-loading", env = "DISABLE_BASE_TAR_GZ_LOADING", action = ArgAction::SetTrue)]
    pub disable_base_tar_gz_loading: bool,

    /// The path to the base tar.gz file to load. Default is a debian 12 deboostrap'ed base system
    #[arg(short = 'b', long = "base-tar-gz-path", env = "BASE_TAR_GZ_PATH")]
    pub base_tar_gz_path: Option<PathBuf>,

    /// Key folder
    #[arg(short = 'k', long = "key-folder", env = "KEY_FOLDER")]
    pub key_folder: Option<PathBuf>,

    /// Disable SO_REUSEPORT for ssh tcp socket
    /// Disabling this may result in issues with IPv6 Ports. Can be disabled safely if net.ipv6.bindv6only = 1 is set
    #[arg(short = 'r', long = "disable-so-reuseport", env = "DISABLE_SO_REUSEPORT", action = ArgAction::SetTrue)]
    pub disable_so_reuseport: bool,

    /// Disable SO_REUSEADDR for ssh tcp socket
    /// Disabling this may result in issues with IPv6 Ports. Can be disabled safely if net.ipv6.bindv6only = 1 is set
    #[arg(short = 's', long = "disable-so-reuseaddr", env = "DISABLE_SO_REUSEADDR", action = ArgAction::SetTrue)]
    pub disable_so_reuseaddr: bool,

    /// Enable SFTP subsystem support
    /// When enabled, SFTP connection attempts will be handled. 
    #[arg(long = "enable-sftp", env = "ENABLE_SFTP", action = ArgAction::SetTrue)]
    pub enable_sftp: bool,

    /// AbuseIPDB API key for checking suspicious IPs
    #[arg(long = "abuse-ip-db-api-key", env = "ABUSE_IP_DB_API_KEY")]
    pub abuse_ip_db_api_key: Option<String>,

    /// Interval in hours for cleaning up expired AbuseIPDB cache entries (default: 24 hours)
    #[arg(long = "abuse-ip-cache-cleanup-hours", env = "ABUSE_IP_CACHE_CLEANUP_HOURS")]
    pub abuse_ip_cache_cleanup_interval_hours: Option<u32>,

    /// Reject all authentication attempts instead of accepting them
    #[arg(long = "reject-all-auth", env = "REJECT_ALL_AUTH", action = ArgAction::SetTrue)]
    pub reject_all_auth: bool,

    /// Disable IPAPI. The free api endpoint does not support TLS https://members.ip-api.com/
    #[arg(long = "disable-ipapi", env = "DISABLE_IPAPI", action = ArgAction::SetTrue)]
    pub disable_ipapi: bool,

    // No default in the macro because it is set further down and needs to be optional to distinguish between CLI and config file precedence
    /// SSH server identification string (default: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4")
    #[arg(long = "server-id", env = "SERVER_ID")]
    pub server_id: Option<String>,

    /// Welcome message system description (default: "Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)")
    #[arg(long = "welcome-message", env = "WELCOME_MESSAGE")]
    pub welcome_message: Option<String>,

    /// Hostname displayed in shell prompt and commands (default: "server01")
    #[arg(long = "hostname", env = "HOSTNAME")]
    pub hostname: Option<String>,
}

#[derive(Debug)]
pub struct App {
    pub interfaces: Vec<SocketAddr>,
    pub database_url: String,
    pub disable_cli_interface: bool,
    pub authentication_banner: Option<String>,
    pub tarpit: bool,
    pub disable_base_tar_gz_loading: bool,
    pub base_tar_gz_path: PathBuf,
    pub key_folder: PathBuf,
    pub disable_so_reuseport: bool,
    pub disable_so_reuseaddr: bool,
    pub enable_sftp: bool,
    pub path_manager: PathManager,
    pub abuse_ip_db_api_key: Option<String>,
    pub abuse_ip_cache_cleanup_interval_hours: u32,
    pub reject_all_auth: bool,
    pub disable_ipapi: bool,
    pub server_id: String,
    pub welcome_message: String,
    pub hostname: String,
}

impl App {
    /// Get the effective key directory (uses PathManager by default, but can be overridden)
    pub fn effective_key_dir(&self) -> &std::path::Path {
        if self.key_folder != self.path_manager.key_dir {
            // CLI/config override is being used
            &self.key_folder
        } else {
            // Use PathManager default
            &self.path_manager.key_dir
        }
    }

    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let path_manager = PathManager::new();
        
        // Log the paths being used
        path_manager.log_paths();
        
        let cli_args = CliArgs::parse();
        
        // Load configuration file
        let config = Self::load_config_file(&path_manager, cli_args.config_file.as_deref())?;
        
        // Merge CLI args with config file, CLI args take precedence
        Ok(Self::merge_config(cli_args, config, path_manager))
    }
    
    fn load_config_file(path_manager: &PathManager, config_path: Option<&std::path::Path>) -> Result<Config, Box<dyn std::error::Error>> {
        let config_path = if let Some(path) = config_path {
            // Use explicit config path
            path.to_path_buf()
        } else {
            // Use PathManager's default config file
            path_manager.config_file()
        };
        
        if config_path.exists() {
            let config_content = std::fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&config_content)?;
            log::info!("Loaded configuration from: {}", config_path.display());
            Ok(config)
        } else {
            log::debug!("No configuration file found at: {}", config_path.display());
            Ok(Config::default())
        }
    }
    
    fn merge_config(cli: CliArgs, config: Config, path_manager: PathManager) -> Self {
        // Parse interfaces from config file strings
        let config_interfaces = if let Some(interface_strings) = config.interfaces {
            interface_strings
                .iter()
                .filter_map(|s| s.parse::<SocketAddr>().ok())
                .collect()
        } else {
            Vec::new()
    };

        Self {
            interfaces: cli.interfaces
                .filter(|v| !v.is_empty())
                .or_else(|| if config_interfaces.is_empty() { None } else { Some(config_interfaces) })
                .unwrap_or(DEFAULT_INTERFACES.to_vec()),
            
            database_url: cli.database_url
                .or(config.database_url)
                .unwrap_or_else(|| "postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot".to_string()),
            
            disable_cli_interface: Self::merge_clap_boolean_with_config(cli.disable_cli_interface, config.disable_cli_interface),
            
            authentication_banner: cli.authentication_banner
                .or(config.authentication_banner),
            
            tarpit: Self::merge_clap_boolean_with_config(cli.tarpit, config.tarpit),
            
            disable_base_tar_gz_loading: Self::merge_clap_boolean_with_config(cli.disable_base_tar_gz_loading, config.disable_base_tar_gz_loading),
            
            base_tar_gz_path: cli.base_tar_gz_path
                .or_else(|| config.base_tar_gz_path.map(PathBuf::from))
                .unwrap_or_else(|| path_manager.base_tar_gz_file()),
            
            key_folder: cli.key_folder
                .or_else(|| config.key_folder.map(PathBuf::from))
                .unwrap_or_else(|| path_manager.key_dir.clone()),
            
            disable_so_reuseport: Self::merge_clap_boolean_with_config(cli.disable_so_reuseport, config.disable_so_reuseport),
            
            disable_so_reuseaddr: Self::merge_clap_boolean_with_config(cli.disable_so_reuseaddr, config.disable_so_reuseaddr),
            
            enable_sftp: Self::merge_clap_boolean_with_config(cli.enable_sftp, config.enable_sftp),
            
            abuse_ip_db_api_key: cli.abuse_ip_db_api_key
                .or(config.abuse_ip_db_api_key),
            
            abuse_ip_cache_cleanup_interval_hours: cli.abuse_ip_cache_cleanup_interval_hours
                .or(config.abuse_ip_cache_cleanup_interval_hours)
                .unwrap_or(24),
            
            reject_all_auth: Self::merge_clap_boolean_with_config(cli.reject_all_auth, config.reject_all_auth),
            
            path_manager,
            disable_ipapi: Self::merge_clap_boolean_with_config(cli.disable_ipapi, config.disable_ipapi),
            
            server_id: cli.server_id
                .or(config.server_id)
                .unwrap_or_else(|| "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4".to_string()),
            
            welcome_message: cli.welcome_message
                .or(config.welcome_message)
                .unwrap_or_else(|| "Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)".to_string()),
            
            hostname: cli.hostname
                .or(config.hostname)
                .unwrap_or_else(|| "server01".to_string()),
        }
    }

    /// Merges a boolean flag from Clap with one from the config file.
    ///
    /// CLI/env (`clap_bool`) takes precedence only if it is `true`.
    ///
    /// If the CLI/env flag is not present (`clap_bool` is `false`), the config value is used.
    fn merge_clap_boolean_with_config(clap_bool: bool, config_bool: Option<bool>) -> bool {
        if clap_bool {
            // Flag was present on CLI or in env, so it's true. Highest precedence.
            true
        } else {
            // Flag was not present, so defer to the config file.
            // If config has a value, use it. Otherwise, default to false.
            config_bool.unwrap_or(false)
        }
    }
}