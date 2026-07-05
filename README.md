# SSH Honeypot

A high-interaction SSH honeypot written in Rust that **pretends to be an Ubuntu server** to lure in attackers — then records everything they do, without ever running a single command for real.

It hands attackers a believable shell (with a fake filesystem, fake processes, fake `ls`/`cat`/`ps`/`free` output), captures their credentials, keystrokes, and SFTP uploads, and ships it all into PostgreSQL. Pair it with the bundled **live dashboard** and you can watch intruders poke around your fake box in real time.

> No attacker command is ever executed. Every shell response is fabricated, so the honeypot can't be turned against the host it runs on.

---

## Why this one?

There are lots of SSH honeypots. This one aims to be the one you actually want to use:

- **Believable sessions.** A Debian/Ubuntu-flavoured fake filesystem (loaded from `base.tar.gz`) plus simulated `ls`, `cat`, `echo`, `date`, `free`, `ps`, `uname` and friends — pipes, redirects, `&&`/`||`, command substitution and all. Attackers waste real time exploring.
- **Everything is logged.** Every connection, auth attempt, command, session, and uploaded file ends up queryable in PostgreSQL.
- **Built-in analysis tools.** A real-time desktop **dashboard**, a **report viewer**, and a CLI **report generator** ship in the same crate.
- **Threat intel, on by default.** Automatic [AbuseIPDB](https://www.abuseipdb.com/) lookups (abuse-confidence scores, Tor-exit detection) and [IPAPI](https://ip-api.com/) geolocation/ISP data, cached in memory + DB.
- **Malware-aware file capture.** SFTP uploads get magic-byte MIME detection, Shannon-entropy scoring, claimed-vs-detected format-mismatch flagging, and hashing.
- **Modern crypto.** Supports post-quantum key exchange (`mlkem768x25519-sha256`) alongside the usual curve25519/DH suites, and accepts password, public-key, and keyboard-interactive auth (so you capture all of them).
- **Safe to deploy.** Ships as a hardened Docker image (`USER 1000`, `cap_drop: ALL`, `no-new-privileges`) built from a `FROM scratch` final layer.

---

## What you get

Three programs build from this repo:

| Binary | What it does |
|--------|--------------|
| `ssh-honeypot` | The honeypot server itself. Listens for SSH, fakes the shell, writes to PostgreSQL. |
| `dashboard-gui` | A live-activity desktop GUI (egui). Shows live sessions, recent auths/connections, top IPs/passwords/usernames, and updates in real time via Postgres `LISTEN`/`NOTIFY`. Double-click any IP/password/session to drill in. |
| `report-gui` | A desktop GUI for generating on-demand IP and password reports against the database. |
| `report-generator` | A CLI for the same reports, output as `text`, `markdown`, or `html` (via bundled MiniJinja templates). |

The dashboard is the fun part — point it at the honeypot's database and watch the attacks roll in.

---

## Quick start (Docker)

The easiest path. This runs the honeypot plus a PostgreSQL instance:

```bash
git clone https://github.com/Lucy-dot-dot/ssh-honeypot.git
cd ssh-honeypot
cp config.toml.example config.toml      # edit if you like
docker compose pull
docker compose up -d && docker compose logs -f ssh-honeypot
```

The compose file publishes the honeypot on ports **22** and **2222** of the host, and exposes Postgres on `127.0.0.1:5432` (so the GUIs can connect locally). By default it runs in **logging mode** (`DISABLE_CLI_INTERFACE=true`): it accepts logins and records credentials, but doesn't hand out a shell. Flip that off in `config.toml` to give attackers the full fake-shell experience.

A prebuilt image is published automatically to `ghcr.io/lucy-dot-dot/ssh-honeypot:master` on every push to `main`/`master`.

### Want the live dashboard?

Build and run the GUI against the same database:

```bash
cargo run --release --bin dashboard-gui
# defaults to postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot
```

Then double-click IPs, passwords, and sessions to dig into them.

---

## How to run it

### Three modes

- **Honeypot mode (default):** accepts every login and drops the attacker into the fake shell.
- **Logging mode (`--reject-all-auth` or `reject_all_auth = true`):** rejects every login but still records every attempt. Lowest-risk.
- **Tarpit mode (`--tarpit`):** answers _veeeerrry_ slowly to burn attacker time.

### Common flags

```bash
# Accept logins and give a fake shell (full honeypot)
cargo run --release

# Reject everyone, just harvest credentials
cargo run --release -- --reject-all-auth

# Slow the attackers down
cargo run --release -- --tarpit

# Add AbuseIPDB threat intel (free key from abuseipdb.com/api)
cargo run --release -- --abuse-ip-db-api-key YOUR_KEY

# Custom listen ports (needs CAP_NET_BIND_SERVICE for ports < 1024)
cargo run --release -- --interface 0.0.0.0:22 --interface [::]:22

# Don't hand out a shell — log auth only, then disconnect
cargo run --release -- --disable-cli-interface
```

### Configuration

Every option can be set via **CLI flag**, **environment variable**, or **TOML config file**, in that order of precedence. Copy `config.toml.example` to `config.toml` for the full, documented set. A few worth knowing:

| Option (flag / env / config key) | What it controls |
|----------------------------------|------------------|
| `--interface` / `INTERFACE` / `interfaces` | Listen addresses, e.g. `0.0.0.0:2222`, `[::]:22` |
| `--database-url` / `DATABASE_URL` / `database_url` | PostgreSQL connection URL |
| `--disable-cli-interface` / `DISABLE_CLI_INTERFACE` | No fake shell — log auth only |
| `--disable-exec` / `DISABLE_EXEC` | Ignore `ssh user@host "cmd"` exec requests (still logged) |
| `--tarpit` / `TARPIT` | Slow responses |
| `--reject-all-auth` / `REJECT_ALL_AUTH` | Deny every login |
| `--enable-sftp` / `ENABLE_SFTP` | Enable SFTP capture (off by default) |
| `--abuse-ip-db-api-key` / `ABUSE_IP_DB_API_KEY` | Enable AbuseIPDB lookups |
| `--disable-ipapi` / `DISABLE_IPAPI` | Disable IPAPI geolocation (free tier is HTTP-only) |
| `--server-id` / `SERVER_ID` | The SSH version string attackers see |
| `--welcome-message` / `WELCOME_MESSAGE` | The MOTD-style banner |
| `--hostname` / `HOSTNAME` | Hostname shown in the fake shell prompt |
| `--authentication-banner` / `AUTHENTICATION_BANNER` | Pre-auth banner text |
| `--base-tar-gz-path` / `BASE_TAR_GZ_PATH` | Custom fake-filesystem archive |
| `--key-folder` / `KEY_FOLDER` | SSH server key directory |

The `config.toml.example` file lists every option with comments and the full set of env-var equivalents.

---

## The reports

Generate an IP or password report from the command line:

```bash
# Everything we know about an attacker IP (text, with geo + threat intel)
cargo run --release --bin report-generator -- ip 203.0.113.42 --format text --extended-info

# Where has this password been seen?
cargo run --release --bin report-generator -- password "root" --format markdown -o root.md
```

An IP report includes connection history, geolocation, ISP/AS, AbuseIPDB abuse-confidence score and Tor flag, total/unique auth attempts, top usernames & passwords, recent attempts, and any commands that IP ran. Password reports show every IP and username that tried that password. Templates live in `templates/` if you want to tweak the output.

The `report-gui` binary is the click-and-point version of the same thing.

---

## What gets stored

All data lands in PostgreSQL. The core tables:

- **`auth`** — every login attempt (username, password, public key, auth type, success), plus point-in-time AbuseIPDB/IPAPI snapshots for that IP
- **`commands`** — every command typed in a session
- **`sessions`** — session lifecycle, including **live** (in-progress) sessions
- **`uploaded_files`** — SFTP uploads with hash, MIME, entropy, and binary blob
- **`conn_track`** — raw connection attempts (source/destination ports)
- **`abuse_ip_cache`** / **`ipapi_cache`** — 24-hour threat-intel caches

Plus a couple of ready-made views that join auth attempts with geo + threat intel (`auth_enriched`, `auth_password_enriched`). Migrations are plain SQL files under `migrations/` and run automatically on startup.

---

## Building from source

Requirements: a recent Rust toolchain (edition 2024), and PostgreSQL if you're not using the Docker setup.

```bash
git clone https://github.com/Lucy-dot-dot/ssh-honeypot.git
cd ssh-honeypot

cargo build --release                       # builds all four binaries
cargo run --release -- --help               # honeypot options
cargo run --release --bin dashboard-gui     # the live dashboard
```

To bind ports below 1024 without root, grant the capability once:

```bash
sudo setcap cap_net_bind_service=+ep target/release/ssh-honeypot
```

### IPv6

The default listeners include `[::]` (IPv6). If IPv6 isn't available, the honeypot logs a harmless bind error and keeps serving IPv4. To actually receive IPv6 traffic inside Docker you need both `ipv6` enabled in the host's `/etc/docker/daemon.json` **and** the `networks:` block at the bottom of `docker-compose.yml` uncommented — see the comments in that file.

---

## Safety & responsibility

This is a **defensive** research tool. A few things to keep in mind:

- **It doesn't execute attacker code.** Shell output is fabricated from a virtual filesystem; nothing an attacker types is ever run for real.
- **Captured data is sensitive.** You'll be collecting credentials, malware samples, and network metadata. Handle retention and disposal per your local laws.
- **Isolate the deployment.** Put it on a network segment that can't reach anything you care about, and monitor it like you would any exposed service.
- **Malware samples are stored in the DB.** SFTP uploads (including binaries) are persisted as `BYTEA`. Treat the database as untrusted.

---

## License

Dual-licensed under **MIT** and **The Unlicense** — pick whichever works for you. See [`LICENSE.MIT`](LICENSE.MIT) and [`LICENSE`](LICENSE).

This software is provided as-is, without warranty of any kind. The authors are not liable for any damage, compromise, or misuse arising from running it. Use it lawfully and responsibly.
