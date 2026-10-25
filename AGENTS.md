# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

This is an SSH honeypot server written in Rust that simulates an Ubuntu-like environment for security research. The honeypot accepts all authentication attempts and provides a fake shell interface without executing any actual commands, making it safe for threat intelligence gathering.

## Common Commands

### Building and Running
- `cargo build --release` - Build optimized release binary
- `cargo run -- --help` - Show available command-line options
- `cargo run` - Run with default settings (listens on 0.0.0.0:2222 and [::]:2222)
- `cargo run -- -i 0.0.0.0:22` - Run on specific interface/port
- `cargo run -- -d postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot` - Use custom PostgreSQL database URL
- `cargo run -- --tarpit` - Enable slow response mode to delay attackers

### Docker Operations
- `docker build -t ssh-honeypot .` - Build Docker image
- `docker-compose up -d` - Run containerized version
- `docker-compose logs -f` - View container logs

**Adding a new workspace crate:** the Docker build uses cargo-chef with a `planner` stage that only copies Cargo manifests and stubs out entry points (`Dockerfile`, "FROM chef AS planner"). When adding a member to `[workspace]` in Cargo.toml, you must also:
1. `COPY <crate>/Cargo.toml <crate>/` in the planner stage
2. Add `<crate>/src` to the `mkdir -p` and a `<crate>/src/lib.rs` stub to the `touch` in the `RUN` right below it

Otherwise `cargo metadata` fails with "failed to load manifest for workspace member /app/<crate>" and the image build breaks in CI, even though `cargo build` works locally. Verify with `docker build --target planner .` before pushing.

### Testing and Development
- `cargo test` - Run unit tests
- `cargo clippy` - Run linter
- `cargo fmt` - Format code

## Architecture

### Core Components

**Main Application Flow** (`src/main.rs`):
- Parses CLI arguments using clap
- Loads or generates SSH host keys 
- Sets up PostgreSQL database handler
- Creates filesystem simulation from base.tar.gz
- Starts SSH server on configured interfaces

**SSH Server Handler** (`src/server.rs`):
- Implements russh server traits
- Handles authentication (accepts all attempts for honeypot purposes)
- Manages shell sessions and command processing
- Records all activity to database
- Supports "tarpit" mode for slowing down attackers

**Database Layer** (`src/db.rs`):
- PostgreSQL backend for storing authentication attempts, commands, and sessions
- Async channel-based communication between server and database
- Tracks IP addresses, usernames, passwords/keys, timestamps, and session duration

**Filesystem Simulation** (`src/shell/filesystem/`):
- Virtual filesystem loaded from base.tar.gz (Debian 12 bootstrap)
- Supports directory navigation, file reading, and basic operations
- Path resolution and symlink following

**Command Handlers** (`src/shell/commands/`):
- Modular command implementations (ls, cat, ps, uname, free, echo, date, pwd, whoami, id, wget, curl, sudo, cd, exit)
- Fake system responses that mimic Ubuntu behavior
- Basic pipe support for commands like grep (`src/shell/commands/dispatcher.rs`)

**SFTP** (`src/sftp.rs`):
- Optional SFTP subsystem support, enabled with `--enable-sftp`
- File operations are served from the virtual filesystem

**MySQL Module** (`mysql/`):
- Separate workspace crate implementing a MySQL wire protocol honeypot (default port 3306)
- Enabled via `--enable-mysql` or the `[mysql]` config section (see config.toml.example)
- Speaks the raw MySQL protocol: v10 handshake, protocol 41 (and legacy) handshake responses, auth switch to `mysql_clear_password` to capture cleartext passwords, OK/ERR packets
- TLS is supported (`enable_tls`, default true): the handshake advertises CLIENT_SSL and, on an SSL request packet, the TCP stream is upgraded via tokio-rustls before the real handshake response is read; serves a generated self-signed certificate or a configured PEM pair (`tls_cert`/`tls_key`). Compression and prepared statements are not supported; queries are logged but answered with an empty OK (no result sets yet)
- Records connections (conn_track), auth attempts (auth, `module = "mysql"`) and queries (commands)

**MSSQL Module** (`mssql/`):
- Separate workspace crate implementing a TDS (Microsoft SQL Server) wire protocol honeypot (default port 1433)
- Enabled via `--enable-mssql` or the `[mssql]` config section (see config.toml.example)
- Speaks the raw TDS protocol: PRELOGIN negotiation, optional TLS (ENCRYPT_OFF advertised by default, TDS 8.0 "strict" TLS-before-prelogin clients supported), LOGIN7 authentication, LOGINACK/ENVCHANGE/DONE responses
- Authentication methods captured (auth_type in the auth table):
  - SQL Server auth (`password`): LOGIN7 passwords are XOR 0xA5 obfuscated UTF-16LE and fully reversible
  - Windows Integrated Auth (`ntlm`): server sends an NTLM type-2 challenge with realistic target info; the client's type-3 response is parsed and stored as a Net-NTLMv2 hash in hashcat -m 5600 format inside the password column. Kerberos/other SSPI mechanisms are recorded as `sspi` and rejected with error 18452
  - Azure AD / Entra ID (`azure_ad_token` for bearer tokens in the SSPI slot, `azure_ad_password` for principal+secret logins)
- `[mssql]` config adds `host_name` / `domain_name` used in NTLM challenges and error tokens
- Post-login SQL batches and RPC calls are logged into commands (no result sets are produced)

**IP Enrichment** (`common/src/abuseipdb.rs`, `common/src/ipapi.rs`):
- Optional AbuseIPDB and ip-api lookups for connecting IPs, with in-memory caching
- Used by both the SSH and MySQL modules

**Report Generator** (`src/bin/report_generator.rs`):
- Separate binary that queries the database and generates per-IP reports (see REPORT_GENERATOR.md)

### Key Files
- `src/main.rs` - Application entry point and server setup
- `src/server.rs` - SSH protocol implementation and session handling
- `common/src/db.rs` - Database operations, data models and the `Module` enum (Ssh/Mysql/Mssql)
- `common/src/tls.rs` - Shared TLS identity/acceptor helpers for the protocol modules
- `src/app.rs` - Configuration (CLI args, env vars, config file merging)
- `src/shell/commands/dispatcher.rs` - Command dispatch and pipe handling
- `src/shell/filesystem/fs2.rs` - Virtual filesystem implementation
- `src/keys.rs` - SSH host key generation and management
- `src/paths.rs` - Platform config/data path management
- `mysql/src/` - MySQL module (config, wire protocol, server)
- `mssql/src/` - MSSQL module (config, TDS protocol, server, NTLM capture)
- `common/migrations/` - PostgreSQL schema migrations
- `base.tar.gz` - Default filesystem content (Debian 12 base system)

### Configuration Options
The application supports extensive configuration via CLI arguments, environment variables, and a TOML config file (`-f`/`CONFIG_FILE`, see config.toml.example). CLI/env takes precedence over the config file:
- Interface binding (`-i`/`INTERFACE`, default 0.0.0.0:2222 and [::]:2222)
- Database URL (`-d`/`DATABASE_URL`, default postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot)
- CLI interface toggle (`-c`/`DISABLE_CLI_INTERFACE`)
- Authentication banner (`-a`/`AUTHENTICATION_BANNER`)
- Tarpit mode (`-t`/`TARPIT`)
- Base filesystem loading (`-g`/`DISABLE_BASE_TAR_GZ_LOADING`, path via `-b`/`BASE_TAR_GZ_PATH`)
- UID assigned to authenticated users (`--default-uid`/`DEFAULT_UID`, default 1000)
- SFTP subsystem support (`--enable-sftp`/`ENABLE_SFTP`)
- Reject all authentication attempts (`--reject-all-auth`/`REJECT_ALL_AUTH`)
- SSH server ID, welcome message, and hostname (`--server-id`, `--welcome-message`, `--hostname`)
- Post-auth BSI MOTD (`--bsi-motd`/`BSI_MOTD`) and NSA MOTD (`--nsa-motd`/`NSA_MOTD`); the BSI notice's EVIDENCE RECORD ID embeds the year and the auth record UUID — auth UUIDs are generated client-side and passed via `DbMessage::RecordAuth.id`, so no database round-trip is needed to know them
- Socket options for IPv6 compatibility (`-r`/`DISABLE_SO_REUSEPORT`, `-s`/`DISABLE_SO_REUSEADDR`)
- AbuseIPDB integration (`--abuse-ip-db-api-key`/`ABUSE_IP_DB_API_KEY`)
- IPAPI toggle (`--disable-ipapi`/`DISABLE_IPAPI`)
- Key folder (`-k`/`KEY_FOLDER`)
- MySQL module toggle (`--enable-mysql`/`ENABLE_MYSQL`); `[mysql]` config section with `interfaces` (default 0.0.0.0:3306 and [::]:3306), `reject_all_auth`, `server_version`, `enable_tls` (default true), `tls_cert`/`tls_key` (optional PEM pair)
- MSSQL module toggle (`--enable-mssql`/`ENABLE_MSSQL`); `[mssql]` config section with `interfaces` (default 0.0.0.0:1433 and [::]:1433), `reject_all_auth`, `server_version`, `enable_tls` (default true), `tls_cert`/`tls_key` (optional PEM pair), `host_name`/`domain_name` for NTLM challenges

### Database
PostgreSQL is required. The docker-compose setup starts a PostgreSQL 16 service with schema initialization from `postgres-init/` and sqlx migrations in `migrations/`. New columns: `auth.module` distinguishes which honeypot module recorded an attempt (`ssh`, `mysql`).

### Security Considerations
This is defensive security software designed for honeypot deployment:
- No actual command execution occurs
- All authentication attempts are logged; they are accepted by default, `--reject-all-auth` rejects them instead
- Session data is recorded for threat analysis
- Containerized deployment with dropped capabilities (cap_drop: ALL, NET_BIND_SERVICE re-added)
- Non-privileged user execution in Docker