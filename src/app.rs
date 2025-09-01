use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};
use crate::paths::PathManager;

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
    pub disable_sftp: Option<bool>,
    pub abuse_ip_db_api_key: Option<String>,
    pub abuse_ip_cache_cleanup_interval_hours: Option<u32>,
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
            disable_sftp: None,
            abuse_ip_db_api_key: None,
            abuse_ip_cache_cleanup_interval_hours: None
        }
    }
}

#[derive(clap::Parser, Debug)]
#[command(version, about = "A small ssh server that allows for advanced honeypot usage", long_about = "A small ssh server that allows for advanced honeypot usage. It provides a fake command interface mimicking ubuntu without any fear of malicious code execution, since no commands are actually executed. It also records all commands in a central sqlite database")]
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

    /// Disable the fake cli interface provided and only save passwords and/or key authentication attempts
    #[arg(short = 'c', long = "disable-cli-interface", env = "DISABLE_CLI_INTERFACE", action = ArgAction::SetTrue)]
    pub disable_cli_interface: Option<bool>,
    
    /// Authentication banner to show. Can make the server more realistic
    #[arg(short, long, env = "AUTHENTICATION_BANNER")]
    pub authentication_banner: Option<String>,

    /// Makes the response veryyyyy slooooooooooowww in order to slow down attackers and "tarpit" them
    #[arg(short, long, env = "TARPIT", action = ArgAction::SetTrue)]
    pub tarpit: Option<bool>,

    /// Disables the base tar.gz loading, which is used to load the base system
    #[arg(short = 'g', long = "disable-base-tar-gz-loading", env = "DISABLE_BASE_TAR_GZ_LOADING", action = ArgAction::SetTrue)]
    pub disable_base_tar_gz_loading: Option<bool>,

    /// The path to the base tar.gz file to load. Default is a debian 12 deboostrap'ed base system
    #[arg(short = 'b', long = "base-tar-gz-path", env = "BASE_TAR_GZ_PATH")]
    pub base_tar_gz_path: Option<PathBuf>,

    /// Key folder
    #[arg(short = 'k', long = "key-folder", env = "KEY_FOLDER")]
    pub key_folder: Option<PathBuf>,

    /// Disable SO_REUSEPORT for ssh tcp socket
    /// Disabling this may result in issues with IPv6 Ports. Can be disabled safely if net.ipv6.bindv6only = 1 is set
    #[arg(short = 'r', long = "disable-so-reuseport", env = "DISABLE_SO_REUSEPORT", action = ArgAction::SetTrue)]
    pub disable_so_reuseport: Option<bool>,

    /// Disable SO_REUSEADDR for ssh tcp socket
    /// Disabling this may result in issues with IPv6 Ports. Can be disabled safely if net.ipv6.bindv6only = 1 is set
    #[arg(short = 's', long = "disable-so-reuseaddr", env = "DISABLE_SO_REUSEADDR", action = ArgAction::SetTrue)]
    pub disable_so_reuseaddr: Option<bool>,

    /// Disable SFTP subsystem support
    /// When disabled, SFTP connection attempts will be logged but not handled
    #[arg(long = "disable-sftp", env = "DISABLE_SFTP", action = ArgAction::SetTrue)]
    pub disable_sftp: Option<bool>,

    /// AbuseIPDB API key for checking suspicious IPs
    #[arg(long = "abuse-ip-db-api-key", env = "ABUSE_IP_DB_API_KEY")]
    pub abuse_ip_db_api_key: Option<String>,

    /// Interval in hours for cleaning up expired AbuseIPDB cache entries (default: 24 hours)
    #[arg(long = "abuse-ip-cache-cleanup-hours", env = "ABUSE_IP_CACHE_CLEANUP_HOURS")]
    pub abuse_ip_cache_cleanup_interval_hours: Option<u32>,
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
    pub disable_sftp: bool,
    pub path_manager: PathManager,
    pub abuse_ip_db_api_key: Option<String>,
    pub abuse_ip_cache_cleanup_interval_hours: u32
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
        
        // Default interfaces
        let default_interfaces = vec![
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 2222),
            SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 2222),
        ];

        // TODO: Handle clap arguments way cleaner. Maybe with an extra function? Because clap boolean flags with `ArgAction::SetTrue` always return `Some(false)`
        let disable_base_tar_gz_loading = if let Some(cli_disable_base_tar_gz_loading) = cli.disable_base_tar_gz_loading {
            if !cli_disable_base_tar_gz_loading && let Some(config_disable_base_tar_gz_loading) = config.disable_base_tar_gz_loading {
                config_disable_base_tar_gz_loading
            } else {
                cli_disable_base_tar_gz_loading
            }
        } else {
            false
        };

        Self {
            interfaces: cli.interfaces
                .filter(|v| !v.is_empty())
                .or_else(|| if config_interfaces.is_empty() { None } else { Some(config_interfaces) })
                .unwrap_or(default_interfaces),
            
            database_url: cli.database_url
                .or(config.database_url)
                .unwrap_or_else(|| "postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot".to_string()),
            
            disable_cli_interface: cli.disable_cli_interface
                .or(config.disable_cli_interface)
                .unwrap_or(false),
            
            authentication_banner: cli.authentication_banner
                .or(config.authentication_banner),
            
            tarpit: cli.tarpit
                .or(config.tarpit)
                .unwrap_or(false),
            
            disable_base_tar_gz_loading,
            
            base_tar_gz_path: cli.base_tar_gz_path
                .or_else(|| config.base_tar_gz_path.map(PathBuf::from))
                .unwrap_or_else(|| path_manager.base_tar_gz_file()),
            
            key_folder: cli.key_folder
                .or_else(|| config.key_folder.map(PathBuf::from))
                .unwrap_or_else(|| path_manager.key_dir.clone()),
            
            disable_so_reuseport: cli.disable_so_reuseport
                .or(config.disable_so_reuseport)
                .unwrap_or(false),
            
            disable_so_reuseaddr: cli.disable_so_reuseaddr
                .or(config.disable_so_reuseaddr)
                .unwrap_or(false),
            
            disable_sftp: cli.disable_sftp
                .or(config.disable_sftp)
                .unwrap_or(false),
            
            abuse_ip_db_api_key: cli.abuse_ip_db_api_key
                .or(config.abuse_ip_db_api_key),
            
            abuse_ip_cache_cleanup_interval_hours: cli.abuse_ip_cache_cleanup_interval_hours
                .or(config.abuse_ip_cache_cleanup_interval_hours)
                .unwrap_or(24),
            
            path_manager,
        }
    }
}