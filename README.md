# SSH Honeypot Server

## About

A sophisticated SSH honeypot server written in Rust that simulates an Ubuntu-like environment to capture and log malicious activities. The server accepts or rejects SSH authentication attempts and provides a fake shell interface without executing any actual commands, making it safe for security research and threat intelligence gathering.

## Features

### Core Honeypot Functionality
- **Safe Command Simulation**: Mimics Ubuntu environment without executing real commands
- **Flexible Authentication**: Can accept all attempts (honeypot mode) or reject all (logging mode)
- **Session Recording**: Tracks complete SSH sessions with timing and command history
- **SFTP Support**: Captures uploaded files with comprehensive threat analysis
- **Tarpit Mode**: Optional slow response mode to delay and frustrate attackers

### IP Intelligence Integration
- **AbuseIPDB Integration**: Automatic threat intelligence lookup with confidence scoring
- **IPAPI Geolocation**: Geographic and ISP information for connecting IPs
- **Dual-Layer Caching**: Memory + database caching for both services (24h TTL)
- **Rate Limit Handling**: Graceful handling of API rate limits with retry logic

### Advanced Monitoring
- **File Upload Analysis**: SFTP uploads analyzed for file type, entropy, and threats
- **Session Tracking**: Complete session lifecycle with start/end times and duration
- **Command Logging**: All entered commands logged with session correlation
- **Connection Tracking**: Basic connection attempt logging

### Database Features
- **PostgreSQL Backend**: Professional-grade database with proper indexing
- **Enriched Views**: `auth_enriched` view combining authentication with IP intelligence
- **Automatic Cache Cleanup**: Configurable cleanup of expired cache entries
- **Migration Support**: Structured database schema evolution

## Usage

### Basic Operation
```bash
# Run with default settings (accepts all auth, listens on 0.0.0.0:2222 and [::]:2222)
cargo run

# Show all available options
cargo run -- --help

# Run in reject-all mode (logs attempts but denies access)
cargo run -- --reject-all-auth

# Enable tarpit mode to slow down attackers
cargo run -- --tarpit
```

### Configuration File
```bash
# Use custom config file
cargo run -- --config /path/to/config.toml

# See config.toml.example for full configuration options
```

### Advanced Options
```bash
# Custom interface and database
cargo run -- --interface 127.0.0.1:2223 --database-url postgresql://user:pass@host/db

# Enable AbuseIPDB integration
cargo run -- --abuse-ip-db-api-key YOUR_API_KEY

# Disable IPAPI geolocation (if you don't want HTTP requests)
cargo run -- --disable-ipapi

# Custom SSH keys directory
cargo run -- --key-folder /secure/keys

# Disable SFTP support
cargo run -- --disable-sftp
```

## Command-Line Options

| Flag | Description | Environment Variable |
|------|-------------|---------------------|
| `-f, --config` | Configuration file path | `CONFIG_FILE` |
| `-i, --interface` | Listen addresses/ports | `INTERFACE` |
| `-d, --database-url` | PostgreSQL connection URL | `DATABASE_URL` |
| `-c, --disable-cli-interface` | Only log auth, no shell simulation | `DISABLE_CLI_INTERFACE` |
| `-a, --authentication-banner` | Custom SSH banner text | `AUTHENTICATION_BANNER` |
| `-t, --tarpit` | Enable slow response mode | `TARPIT` |
| `-g, --disable-base-tar-gz-loading` | Skip filesystem loading | `DISABLE_BASE_TAR_GZ_LOADING` |
| `-b, --base-tar-gz-path` | Custom filesystem archive path | `BASE_TAR_GZ_PATH` |
| `-k, --key-folder` | SSH keys directory | `KEY_FOLDER` |
| `--enable-sftp` | Enable SFTP subsystem (disabled by default) | `ENABLE_SFTP` |
| `--abuse-ip-db-api-key` | AbuseIPDB API key | `ABUSE_IP_DB_API_KEY` |
| `--abuse-ip-cache-cleanup-hours` | Cache cleanup interval | `ABUSE_IP_CACHE_CLEANUP_HOURS` |
| `--reject-all-auth` | Reject all authentication attempts | `REJECT_ALL_AUTH` |
| `--disable-ipapi` | Disable IPAPI geolocation | `DISABLE_IPAPI` |

## Configuration

### Directory Structure
```
~/.config/ssh-honeypot/          # Configuration directory (XDG compliant)
├── config.toml                  # Main configuration file
└── keys/                        # SSH server keys
    ├── ed25519
    ├── rsa  
    └── ecdsa

~/.local/share/ssh-honeypot/     # Data directory
└── base.tar.gz                  # Filesystem archive
```

### Configuration Precedence
1. Command-line arguments (highest priority)
2. Configuration file values
3. Environment variables
4. XDG directory defaults
5. Hard-coded defaults (lowest priority)

## Database Schema

### Core Tables
- **`auth`**: All SSH authentication attempts with credentials
- **`commands`**: Commands entered during SSH sessions
- **`sessions`**: Session metadata with start/end times
- **`uploaded_files`**: SFTP uploads with threat analysis
- **`conn_track`**: Basic connection attempt logging

### Cache Tables
- **`abuse_ip_cache`**: AbuseIPDB threat intelligence cache
- **`ipapi_cache`**: IPAPI geolocation data cache

### Views
- **`auth_enriched`**: Comprehensive view merging authentication attempts with IP intelligence from both AbuseIPDB and IPAPI, with AbuseIPDB taking precedence for overlapping fields

## Security Features

### Threat Detection
- **File Upload Analysis**: Magic-based MIME detection, entropy analysis, format mismatch detection
- **IP Reputation**: Automatic AbuseIPDB lookups with confidence scoring
- **Tor Detection**: Identifies Tor exit nodes via AbuseIPDB
- **Geographic Profiling**: Country and ISP identification via IPAPI

### Configuration Security
- **XDG Compliance**: Uses standard system directories with proper permissions
- **Key Management**: SSH keys stored securely in dedicated directory
- **No Secret Exposure**: Configuration files don't contain sensitive data
- **Path Validation**: All file paths validated and resolved safely

### Operational Modes
- **Honeypot Mode** (default): Accepts all authentication, provides interactive shell
- **Logging Mode** (`--reject-all-auth`): Rejects all authentication, logs attempts only
- **Tarpit Mode** (`--tarpit`): Deliberately slow responses to waste attacker time

## Requirements

- **Rust 1.70+**: Modern Rust toolchain
- **PostgreSQL**: Database backend for storing honeypot data
- **Network Access**: For IP intelligence APIs (optional)
- **Elevated Privileges**: For binding to ports < 1000 (use `setcap cap_net_bind_service`)

## Installation

```bash
# Clone the repo
git clone <repository-url>

# Change directory to the repo root
cd ssh-honeypot

# Create configuration file
touch config.toml

# Pull latest postgres docker image
docker compose pull

# Build the server. Redo this step if you `git pull` new changes
docker compose build

# Run the server
docker compose up -d && docker compose logs -f ssh-honeypot
```

If you want to save the generated keys for faster startup:

```bash
# Clone the repo
git clone <repository-url>

# Change directory to the repo root
cd ssh-honeypot

# Create configuration file
touch config.toml

# Create keys directory and set permissions to allow the container to write to it
mkdir keys
chown 1000:1000 keys

# Now patch docker-compose.yml and add this to the volumes section:
#   - ./keys:keys

# Pull latest postgres docker image
docker compose pull

# Build the server. Redo this step if you `git pull` new changes
docker compose build

# Run the server
docker compose up -d && docker compose logs -f ssh-honeypot
```

## Development

### Build Commands
```bash
cargo build              # Debug build
cargo build --release    # Optimized build
cargo check              # Quick compilation check
cargo run -- --help     # Show all options
```

### Configuration
See `config.toml.example` for a fully documented configuration file with all available options.

### Database Migrations
- `001_initial_schema.sql`: Core tables (auth, commands, sessions, uploaded_files, abuse_ip_cache)
- `002_conn_track.sql`: Connection tracking table
- `003_ipapi_cache.sql`: IPAPI geolocation cache table  
- `004_auth_enriched_view.sql`: Enriched authentication view

## Architecture

### Core Components
1. **SSH Server** (`src/server.rs`): Handles SSH connections and authentication
2. **Database Layer** (`src/db.rs`): Async message-based database operations
3. **SFTP Handler** (`src/sftp.rs`): File upload capture and analysis
4. **Shell Simulation** (`src/shell/`): Virtual filesystem and command responses
5. **IP Intelligence** (`src/abuseipdb.rs`, `src/ipapi.rs`): Threat and geolocation APIs
6. **Configuration** (`src/app.rs`): Multi-layer configuration system

### Key Design Patterns
- **Async Architecture**: Tokio-based async handling
- **Message Passing**: Database operations via mpsc channels
- **Virtual Filesystem**: Loads from base.tar.gz for realistic content
- **Dual Caching**: Memory + database caching for API responses
- **XDG Compliance**: Standard directory structure with fallbacks

## API Integration

### AbuseIPDB
- **Purpose**: Threat intelligence and abuse confidence scoring
- **Caching**: 24-hour TTL with memory + database layers
- **Rate Limiting**: Graceful handling with retry-after logic
- **Data**: Confidence scores, country codes, Tor detection, report counts

### IPAPI
- **Purpose**: Geographic and ISP information  
- **Caching**: 24-hour TTL with memory + database layers
- **Note**: Free tier uses HTTP (no HTTPS) - disable with `--disable-ipapi`, `DISABLE_IPAPI` environment variable or `disable_ipapi = true` in the toml config file
- **Data**: Country, region, city, coordinates, timezone, ISP, organization

## Security Considerations

This is a honeypot designed for **defensive security research**. The code deliberately simulates vulnerability while maintaining actual system security by never executing real commands.

### Data Privacy
- All captured data (credentials, commands, files) should be handled according to applicable privacy laws
- Consider data retention policies and secure disposal procedures
- Ensure compliance with local regulations regarding data collection

### Network Security  
- Deploy in isolated network segments when possible
- Monitor for unusual traffic patterns that might indicate compromise
- Regularly review logs for unexpected behavior

## Legal Disclaimer

This software is provided "as-is" without any warranty or guarantee of any kind, either expressed or implied. The author(s) of this honeypot SSH server are not liable for any damages, attacks, security breaches, data loss, system compromises, or other negative consequences that may arise from using this software.

By installing and using this software, you acknowledge that:

1. You are using this software at your own risk
2. The author(s) bear no responsibility for any security vulnerabilities that may exist in the code  
3. The author(s) are not responsible for any attacks directed at your systems as a result of using this software
4. No fitness for a particular purpose is guaranteed
5. The author(s) are not liable for any misuse of the collected data

This tool is intended for security research and educational purposes only. Users are responsible for deploying it in compliance with all applicable laws and regulations in their jurisdiction.

## License

Dual licensed under MIT and UNLICENSE - choose whatever license your lawyer is happy with.