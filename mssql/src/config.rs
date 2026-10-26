use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

/// Default interfaces for the MSSQL module (IPv4 and IPv6, port 1433)
pub const DEFAULT_MSSQL_INTERFACES: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1433),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 1433),
];

/// Default server version string reported in the prelogin / login ack.
/// Mimics a SQL Server 2022 RTM installation.
pub const DEFAULT_MSSQL_SERVER_VERSION: &str = "16.0.1000.6";

/// Default Windows computer name used in NTLM challenges and error tokens.
pub const DEFAULT_MSSQL_HOST_NAME: &str = "WIN-SERVER01";

/// `[mssql]` section of the configuration file. All fields optional,
/// mirroring the style of the `[mysql]` section.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct MssqlConfig {
    /// Enable the MSSQL module. Can also be toggled via --enable-mssql
    pub enabled: Option<bool>,
    /// Network interfaces to listen on, stored as strings for TOML compatibility
    pub interfaces: Option<Vec<String>>,
    /// Reject all authentication attempts instead of accepting them
    pub reject_all_auth: Option<bool>,
    /// Server version string reported in prelogin and the login ack
    pub server_version: Option<String>,
    /// Support TLS connections (ENCRYPT_OFF is advertised so clients can
    /// encrypt the login sequence). Enabled by default, like a modern
    /// SQL Server installation.
    pub enable_tls: Option<bool>,
    /// Optional PEM certificate chain to serve instead of a generated
    /// self-signed certificate
    pub tls_cert: Option<String>,
    /// Optional PEM private key belonging to tls_cert
    pub tls_key: Option<String>,
    /// Windows computer name used in NTLM challenges and error tokens
    pub host_name: Option<String>,
    /// NetBIOS domain name presented in NTLM challenges. For a standalone
    /// server this is normally identical to the computer name.
    pub domain_name: Option<String>,
}

/// Fully resolved MSSQL module configuration with defaults applied
#[derive(Debug, Clone)]
pub struct MssqlSettings {
    pub enabled: bool,
    pub interfaces: Vec<SocketAddr>,
    pub reject_all_auth: bool,
    pub server_version: String,
    pub enable_tls: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub host_name: String,
    pub domain_name: String,
}

impl MssqlConfig {
    /// Resolve the config into concrete settings.
    /// `enabled` is already merged with the CLI flag by the caller.
    pub fn resolve(self, enabled: bool) -> MssqlSettings {
        let interfaces = self
            .interfaces
            .map(|strings| {
                strings
                    .iter()
                    .filter_map(|s| s.parse::<SocketAddr>().ok())
                    .collect::<Vec<_>>()
            })
            .filter(|v: &Vec<SocketAddr>| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_MSSQL_INTERFACES.to_vec());

        let host_name = self
            .host_name
            .unwrap_or_else(|| DEFAULT_MSSQL_HOST_NAME.to_string());
        // A standalone server presents its computer name as the NTLM domain
        let domain_name = self.domain_name.unwrap_or_else(|| host_name.clone());

        MssqlSettings {
            enabled,
            interfaces,
            reject_all_auth: self.reject_all_auth.unwrap_or(false),
            server_version: self
                .server_version
                .unwrap_or_else(|| DEFAULT_MSSQL_SERVER_VERSION.to_string()),
            enable_tls: self.enable_tls.unwrap_or(true),
            tls_cert: self.tls_cert.map(PathBuf::from),
            tls_key: self.tls_key.map(PathBuf::from),
            host_name,
            domain_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn tls_defaults_to_enabled_with_generated_certificate() {
        let settings = MssqlConfig::default().resolve(true);
        assert!(settings.enable_tls);
        assert!(settings.tls_cert.is_none());
        assert!(settings.tls_key.is_none());
        assert_eq!(settings.host_name, DEFAULT_MSSQL_HOST_NAME);
        // Standalone: domain defaults to the computer name
        assert_eq!(settings.domain_name, settings.host_name);
    }

    #[test]
    fn tls_can_be_disabled_and_identity_paths_resolved() {
        let config: MssqlConfig = toml::from_str(
            r#"
            enable_tls = false
            tls_cert = "/tmp/cert.pem"
            tls_key = "/tmp/key.pem"
            host_name = "SQLBOX"
            domain_name = "CORP"
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
        assert_eq!(settings.host_name, "SQLBOX");
        assert_eq!(settings.domain_name, "CORP");
    }

    #[test]
    fn interfaces_default_to_1433() {
        let settings = MssqlConfig::default().resolve(false);
        assert_eq!(settings.interfaces, DEFAULT_MSSQL_INTERFACES.to_vec());
        assert!(!settings.enabled);
    }
}
