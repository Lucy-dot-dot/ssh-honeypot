use std::path::PathBuf;
use directories::ProjectDirs;
use std::fs;

/// Centralized path management for the SSH honeypot
/// Handles XDG directories and fallbacks consistently across the application
#[derive(Debug, Clone)]
pub struct PathManager {
    /// Base directory for configuration and data
    pub _base_dir: PathBuf,
    /// Directory for configuration files
    pub config_dir: PathBuf,
    /// Directory for server keys
    pub key_dir: PathBuf,
    /// Directory for data files (databases, logs, etc.)
    pub data_dir: PathBuf,
}

impl PathManager {
    /// Create a new PathManager, using XDG directories when available
    pub fn new() -> Self {
        if let Some(proj_dirs) = ProjectDirs::from("", "", "ssh-honeypot") {
            // Try XDG directories first
            let config_dir = proj_dirs.config_dir().to_path_buf();
            let data_dir = proj_dirs.data_dir().to_path_buf();
            let key_dir = config_dir.join("keys");

            // Test if we can actually create the directories
            if let Err(_) = fs::create_dir_all(&config_dir) {
                log::warn!("Cannot create XDG config directory {config_dir:?}, falling back to current directory");
                return Self::new_fallback();
            }
            if let Err(_) = fs::create_dir_all(&data_dir) {
                log::warn!("Cannot create XDG data directory {data_dir:?}, falling back to current directory");
                return Self::new_fallback();
            }
            if let Err(_) = fs::create_dir_all(&key_dir) {
                log::warn!("Cannot create XDG key directory {key_dir:?}, falling back to current directory");
                return Self::new_fallback();
            }

            log::info!("Using XDG directories for configuration");
            log::info!("Paths: {config_dir:?} {data_dir:?} {key_dir:?} ");

            Self {
                _base_dir: config_dir.clone(),
                config_dir,
                key_dir,
                data_dir,
            }
        } else {
            Self::new_fallback()
        }
    }

    /// Create PathManager with fallback directories (current directory)
    fn new_fallback() -> Self {
        log::info!("Using fallback directories for configuration");
        // Fallback to current directory (Docker-friendly)
        let base_dir = PathBuf::from(".");
        let config_dir = base_dir.clone();
        let data_dir = base_dir.clone();
        let key_dir = base_dir.join("keys");
        
        Self {
            _base_dir: base_dir,
            config_dir,
            key_dir,
            data_dir,
        }
    }
    
    /// Get the default configuration file path
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// Get the default base.tar.gz file path
    pub fn base_tar_gz_file(&self) -> PathBuf {
        self.data_dir.join("base.tar.gz")
    }
    
    /// Log the current directory configuration
    pub fn log_paths(&self) {
        log::info!("Path configuration:");
        log::info!("  Config directory: {}", self.config_dir.display());
        log::info!("  Key directory: {}", self.key_dir.display());
        log::info!("  Data directory: {}", self.data_dir.display());
        log::info!("  Config file: {}", self.config_file().display());
    }
}

impl Default for PathManager {
    fn default() -> Self {
        Self::new()
    }
}

