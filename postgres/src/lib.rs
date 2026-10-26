//! PostgreSQL honeypot module.
//!
//! Mirrors the MySQL module: every connection is recorded in conn_track,
//! every login attempt in auth (module = "postgres") and every query in
//! commands. There is no result set generation; the goal is credential
//! capture and brute-force intelligence.
//!
//! Authentication: the server only advertises cleartext password
//! authentication (AuthenticationCleartextPassword). MD5 and SCRAM-SHA-256
//! are intentionally never offered so clients transmit the password in the
//! clear.
pub mod config;
pub mod protocol;
pub mod server;

pub use config::{PostgresConfig, PostgresSettings};
