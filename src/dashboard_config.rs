//! Dashboard GUI preferences, persisted to `dashboard.toml` in the project's
//! config directory (same `ssh-honeypot` project dirs used by the honeypot
//! server, so it lands next to `config.toml`).
//!
//! The dashboard config is intentionally separate from the honeypot config: it
//! holds user-facing view preferences that change at runtime from the GUI,
//! whereas the honeypot config is operational and read once at startup.
//!
//! Loading is best-effort — a missing or malformed file simply falls back to
//! defaults so the GUI always starts. Saving is also best-effort; errors are
//! logged and never fatal.

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const CONFIG_FILE_NAME: &str = "dashboard.toml";

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DashboardConfig {
    /// IP addresses hidden from every dashboard view (recent feeds, live
    /// sessions, top IPs, ...). Compared case-insensitively after trimming.
    #[serde(default)]
    pub excluded_ips: Vec<String>,

    /// Whether geolocation columns/fields (country, city, ISP, org) are drawn.
    /// Exposed as a quick toggle in the dashboard hotbar.
    #[serde(default = "default_show_geolocation")]
    pub show_geolocation: bool,
}

fn default_show_geolocation() -> bool {
    true
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            excluded_ips: Vec::new(),
            show_geolocation: true,
        }
    }
}

impl DashboardConfig {
    /// Resolve the dashboard config file path, mirroring the project dirs used
    /// by the honeypot (`ssh-honeypot`). Falls back to the current directory if
    /// the platform exposes no config dir.
    pub fn config_path() -> PathBuf {
        if let Some(proj_dirs) = ProjectDirs::from("", "", "ssh-honeypot") {
            proj_dirs.config_dir().join(CONFIG_FILE_NAME)
        } else {
            PathBuf::from(CONFIG_FILE_NAME)
        }
    }

    /// Load the dashboard config from disk, returning defaults if the file is
    /// missing or unreadable. Never panics — the GUI must always be usable.
    pub fn load() -> Self {
        let path = Self::config_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => match toml::from_str::<DashboardConfig>(&contents) {
                Ok(cfg) => {
                    log::info!("Loaded dashboard config from {}", path.display());
                    cfg
                }
                Err(e) => {
                    log::warn!(
                        "Failed to parse dashboard config at {}: {e}; using defaults",
                        path.display()
                    );
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::debug!("No dashboard config at {}, using defaults", path.display());
                Self::default()
            }
            Err(e) => {
                log::warn!(
                    "Failed to read dashboard config at {}: {e}; using defaults",
                    path.display()
                );
                Self::default()
            }
        }
    }

    /// Persist the dashboard config to disk. Errors are logged, not fatal.
    pub fn save(&self) {
        let path = Self::config_path();
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            log::warn!(
                "Failed to create dashboard config dir {}: {e}",
                parent.display()
            );
            return;
        }
        match toml::to_string_pretty(self) {
            Ok(text) => {
                if let Err(e) = std::fs::write(&path, text) {
                    log::warn!(
                        "Failed to write dashboard config to {}: {e}",
                        path.display()
                    );
                }
            }
            Err(e) => log::warn!("Failed to serialize dashboard config: {e}"),
        }
    }

    /// True if `ip` matches any excluded entry (case-insensitive, trimmed).
    pub fn is_excluded(&self, ip: &str) -> bool {
        let ip = ip.trim();
        self.excluded_ips
            .iter()
            .any(|e| e.trim().eq_ignore_ascii_case(ip))
    }
}
