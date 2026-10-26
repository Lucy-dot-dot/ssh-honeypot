use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

/// Default interfaces for the PostgreSQL module (IPv4 and IPv6, port 5432)
pub const DEFAULT_POSTGRES_INTERFACES: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 5432),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 5432),
];

/// Default server_version parameter reported after authentication.
/// Mimics an Ubuntu 22.04 PostgreSQL 15 apt package build.
pub const DEFAULT_POSTGRES_SERVER_VERSION: &str = "15.6 (Ubuntu 15.6-1.pgdg22.04+1)";

/// `[postgres]` section of the configuration file. All fields optional,
/// mirroring the style of the MySQL and MSSQL modules.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct PostgresConfig {
    /// Enable the PostgreSQL module. Can also be toggled via --enable-postgres
    pub enabled: Option<bool>,
    /// Network interfaces to listen on, stored as strings for TOML compatibility
    pub interfaces: Option<Vec<String>>,
    /// Reject all authentication attempts instead of accepting them
    pub reject_all_auth: Option<bool>,
    /// server_version parameter reported to clients
    pub server_version: Option<String>,
    /// Support TLS connections (SSLRequest answered with 'S'). Enabled by
    /// default, like a modern PostgreSQL server.
    pub enable_tls: Option<bool>,
    /// Optional PEM certificate chain to serve instead of a generated
    /// self-signed certificate
    pub tls_cert: Option<String>,
    /// Optional PEM private key belonging to tls_cert
    pub tls_key: Option<String>,
}

/// Fully resolved PostgreSQL module configuration with defaults applied
#[derive(Debug, Clone)]
pub struct PostgresSettings {
    pub enabled: bool,
    pub interfaces: Vec<SocketAddr>,
    pub reject_all_auth: bool,
    pub server_version: String,
    pub enable_tls: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl PostgresConfig {
    /// Resolve the config into concrete settings.
    /// `enabled` is already merged with the CLI flag by the caller.
    pub fn resolve(self, enabled: bool) -> PostgresSettings {
        let interfaces = self
            .interfaces
            .map(|strings| {
                strings
                    .iter()
                    .filter_map(|s| s.parse::<SocketAddr>().ok())
                    .collect::<Vec<_>>()
            })
            .filter(|v: &Vec<SocketAddr>| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_POSTGRES_INTERFACES.to_vec());

        PostgresSettings {
            enabled,
            interfaces,
            reject_all_auth: self.reject_all_auth.unwrap_or(false),
            server_version: self
                .server_version
                .unwrap_or_else(|| DEFAULT_POSTGRES_SERVER_VERSION.to_string()),
            enable_tls: self.enable_tls.unwrap_or(true),
            tls_cert: self.tls_cert.map(PathBuf::from),
            tls_key: self.tls_key.map(PathBuf::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn tls_defaults_to_enabled_with_generated_certificate() {
        let settings = PostgresConfig::default().resolve(true);
        assert!(settings.enable_tls);
        assert!(settings.tls_cert.is_none());
        assert!(settings.tls_key.is_none());
    }

    #[test]
    fn tls_can_be_disabled_and_identity_paths_resolved() {
        let config: PostgresConfig = toml::from_str(
            r#"
            enable_tls = false
            tls_cert = "/tmp/cert.pem"
            tls_key = "/tmp/key.pem"
        "#,
        )
        .unwrap();
        let settings = config.resolve(true);
        assert!(!settings.enable_tls);
        assert_eq!(
            settings.tls_cert.as_deref(),
            Some(Path::new("/tmp/cert.pem"))
        );
        assert_eq!(settings.tls_key.as_deref(), Some(Path::new("/tmp/key.pem")));
    }

    #[test]
    fn interfaces_default_to_port_5432() {
        let settings = PostgresConfig::default().resolve(false);
        assert_eq!(settings.interfaces, DEFAULT_POSTGRES_INTERFACES.to_vec());
        assert!(!settings.enabled);
    }
}
