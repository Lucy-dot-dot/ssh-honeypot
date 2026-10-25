//! MSSQL (Microsoft SQL Server / TDS) honeypot module.
//!
//! Mirrors the MySQL module: every connection is recorded in conn_track,
//! every login attempt in auth (module = "mssql") and every post-login
//! batch/RPC request in commands. There is no result set generation; the
//! goal is credential capture and brute-force intelligence.
//!
//! Supported authentication methods:
//! - SQL Server authentication (user/password in LOGIN7, reversibly
//!   obfuscated with a XOR 0xA5 byte transform)
//! - Windows Integrated Auth via NTLM (Net-NTLMv2 capture for offline
//!   cracking); Kerberos/other SSPI mechanisms are recorded and rejected
//! - Azure AD / Entra ID auth (bearer token or principal+secret)
pub mod config;
pub mod protocol;
pub mod server;

pub use config::{MssqlConfig, MssqlSettings};
