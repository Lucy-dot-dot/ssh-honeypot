//! Application-native metrics for the honeypot.
//!
//! A global, lock-free counter registry ([`AtomicU64`] fields behind a
//! [`OnceLock`]) that is incremented as honeypot events are processed
//! (centrally in `run_db_handler`, so all modules are covered), plus an
//! optional Prometheus text-format (version 0.0.4) HTTP endpoint for
//! scraping it.
//!
//! The registry itself is always active: incrementing a counter is a single
//! relaxed atomic add, so events are counted even while the exposition
//! endpoint is disabled. The endpoint only starts when enabled via the
//! `[metrics]` config section or `--enable-metrics`.

use crate::db::Module;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Default interfaces for the metrics endpoint: loopback only, port 9154.
/// The endpoint is disabled by default; these defaults only apply once it
/// is enabled and no interfaces are configured.
pub const DEFAULT_METRICS_INTERFACES: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9154),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 9154),
];

/// `[metrics]` section of the configuration file. All fields optional,
/// mirroring the style of the other module sections.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct MetricsConfig {
    /// Enable the Prometheus metrics endpoint. Can also be toggled via
    /// --enable-metrics
    pub enabled: Option<bool>,
    /// Network interfaces to listen on, stored as strings for TOML
    /// compatibility. Defaults to loopback on port 9154
    pub interfaces: Option<Vec<String>>,
}

/// Fully resolved metrics endpoint configuration with defaults applied
#[derive(Debug, Clone)]
pub struct MetricsSettings {
    pub enabled: bool,
    pub interfaces: Vec<SocketAddr>,
}

impl MetricsConfig {
    /// Resolve the config into concrete settings.
    /// `enabled` is already merged with the CLI flag by the caller.
    pub fn resolve(self, enabled: bool) -> MetricsSettings {
        let interfaces = self
            .interfaces
            .map(|strings| {
                strings
                    .iter()
                    .filter_map(|s| s.parse::<SocketAddr>().ok())
                    .collect::<Vec<_>>()
            })
            .filter(|v: &Vec<SocketAddr>| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_METRICS_INTERFACES.to_vec());

        MetricsSettings {
            enabled,
            interfaces,
        }
    }
}

/// Per-module event counters. All counters are monotonic except
/// `sessions_active`, which is a gauge.
#[derive(Debug, Default)]
pub struct ModuleMetrics {
    /// Accepted TCP connections
    pub connections_total: AtomicU64,
    /// Authentication attempts seen
    pub auth_attempts_total: AtomicU64,
    /// Successful authentication attempts
    pub auth_success_total: AtomicU64,
    /// Failed authentication attempts
    pub auth_failure_total: AtomicU64,
    /// Recorded commands / queries
    pub commands_total: AtomicU64,
    /// Sessions that started
    pub sessions_started_total: AtomicU64,
    /// Sessions that ended
    pub sessions_ended_total: AtomicU64,
    /// Currently active sessions (gauge)
    pub sessions_active: AtomicU64,
}

/// Global metrics registry. Obtain it via [`metrics`].
#[derive(Debug)]
pub struct Metrics {
    pub ssh: ModuleMetrics,
    pub mysql: ModuleMetrics,
    pub mssql: ModuleMetrics,
    pub postgres: ModuleMetrics,
    /// Files uploaded via SFTP
    pub file_uploads_total: AtomicU64,
    /// Bytes uploaded via SFTP
    pub file_upload_bytes_total: AtomicU64,
    /// Database messages processed by the db handler
    pub db_messages_total: AtomicU64,
    /// Database write errors in the db handler
    pub db_errors_total: AtomicU64,
    /// 1 while the database handler task is running (gauge)
    pub db_handler_live: AtomicU64,
    started: Instant,
}

impl Metrics {
    fn new() -> Self {
        Self {
            ssh: ModuleMetrics::default(),
            mysql: ModuleMetrics::default(),
            mssql: ModuleMetrics::default(),
            postgres: ModuleMetrics::default(),
            file_uploads_total: AtomicU64::new(0),
            file_upload_bytes_total: AtomicU64::new(0),
            db_messages_total: AtomicU64::new(0),
            db_errors_total: AtomicU64::new(0),
            db_handler_live: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    fn module(&self, module: Module) -> &ModuleMetrics {
        match module {
            Module::Ssh => &self.ssh,
            Module::Mysql => &self.mysql,
            Module::Mssql => &self.mssql,
            Module::Postgres => &self.postgres,
        }
    }

    pub fn record_connection(&self, module: Module) {
        self.module(module)
            .connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_auth(&self, module: Module, successful: bool) {
        let m = self.module(module);
        m.auth_attempts_total.fetch_add(1, Ordering::Relaxed);
        if successful {
            m.auth_success_total.fetch_add(1, Ordering::Relaxed);
        } else {
            m.auth_failure_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_command(&self, module: Module) {
        self.module(module)
            .commands_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_session_start(&self, module: Module) {
        let m = self.module(module);
        m.sessions_started_total.fetch_add(1, Ordering::Relaxed);
        m.sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_session_end(&self, module: Module) {
        let m = self.module(module);
        m.sessions_ended_total.fetch_add(1, Ordering::Relaxed);
        // Saturating decrement: a crashed session that never sent an end
        // message must not make the gauge wrap around.
        let _ = m
            .sessions_active
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    pub fn record_file_upload(&self, bytes: u64) {
        self.file_uploads_total.fetch_add(1, Ordering::Relaxed);
        self.file_upload_bytes_total
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_db_message(&self) {
        self.db_messages_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_db_error(&self) {
        self.db_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_db_handler_live(&self, live: bool) {
        self.db_handler_live
            .store(u64::from(live), Ordering::Relaxed);
    }

    pub fn uptime_seconds(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Render the registry in Prometheus text format (version 0.0.4).
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);

        let modules: [(&str, &ModuleMetrics); 4] = [
            (Module::Ssh.as_str(), &self.ssh),
            (Module::Mysql.as_str(), &self.mysql),
            (Module::Mssql.as_str(), &self.mssql),
            (Module::Postgres.as_str(), &self.postgres),
        ];

        push_module_family(
            &mut out,
            "honeypot_connections_total",
            "Accepted TCP connections by honeypot module.",
            "counter",
            &modules,
            |m| m.connections_total.load(Ordering::Relaxed),
        );
        push_module_family(
            &mut out,
            "honeypot_auth_attempts_total",
            "Authentication attempts seen by honeypot module.",
            "counter",
            &modules,
            |m| m.auth_attempts_total.load(Ordering::Relaxed),
        );
        push_module_family(
            &mut out,
            "honeypot_auth_success_total",
            "Successful authentication attempts by honeypot module.",
            "counter",
            &modules,
            |m| m.auth_success_total.load(Ordering::Relaxed),
        );
        push_module_family(
            &mut out,
            "honeypot_auth_failure_total",
            "Failed authentication attempts by honeypot module.",
            "counter",
            &modules,
            |m| m.auth_failure_total.load(Ordering::Relaxed),
        );
        push_module_family(
            &mut out,
            "honeypot_commands_total",
            "Recorded commands and queries by honeypot module.",
            "counter",
            &modules,
            |m| m.commands_total.load(Ordering::Relaxed),
        );
        push_module_family(
            &mut out,
            "honeypot_sessions_started_total",
            "Sessions started by honeypot module.",
            "counter",
            &modules,
            |m| m.sessions_started_total.load(Ordering::Relaxed),
        );
        push_module_family(
            &mut out,
            "honeypot_sessions_ended_total",
            "Sessions ended by honeypot module.",
            "counter",
            &modules,
            |m| m.sessions_ended_total.load(Ordering::Relaxed),
        );
        push_module_family(
            &mut out,
            "honeypot_sessions_active",
            "Currently active sessions by honeypot module.",
            "gauge",
            &modules,
            |m| m.sessions_active.load(Ordering::Relaxed),
        );

        push_scalar_family(
            &mut out,
            "honeypot_file_uploads_total",
            "Files uploaded via SFTP.",
            "counter",
            self.file_uploads_total.load(Ordering::Relaxed),
        );
        push_scalar_family(
            &mut out,
            "honeypot_file_upload_bytes_total",
            "Bytes uploaded via SFTP.",
            "counter",
            self.file_upload_bytes_total.load(Ordering::Relaxed),
        );
        push_scalar_family(
            &mut out,
            "honeypot_db_messages_total",
            "Database messages processed by the db handler.",
            "counter",
            self.db_messages_total.load(Ordering::Relaxed),
        );
        push_scalar_family(
            &mut out,
            "honeypot_db_errors_total",
            "Database write errors in the db handler.",
            "counter",
            self.db_errors_total.load(Ordering::Relaxed),
        );
        push_scalar_family(
            &mut out,
            "honeypot_db_handler_live",
            "1 while the database handler task is running.",
            "gauge",
            self.db_handler_live.load(Ordering::Relaxed),
        );

        let name = "honeypot_uptime_seconds";
        push_family_header(
            &mut out,
            name,
            "Time since the metrics registry was initialized.",
            "gauge",
        );
        out.push_str(name);
        out.push(' ');
        out.push_str(&format!("{:.3}\n", self.uptime_seconds()));

        out
    }
}

/// Global metrics registry accessor. The registry is process-wide, created
/// on first use and never replaced.
pub fn metrics() -> &'static Metrics {
    static METRICS: OnceLock<Metrics> = OnceLock::new();
    METRICS.get_or_init(Metrics::new)
}

/// Minimal hand-rolled Prometheus exposition server (HTTP/1.1, text format
/// version 0.0.4). Serves `GET /metrics` on every accepted connection and
/// closes the connection after each response.
#[derive(Debug, Default, Clone, Copy)]
pub struct MetricsServer;

impl MetricsServer {
    pub async fn run_on_listener(self, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    tokio::spawn(handle_connection(stream));
                }
                Err(err) => {
                    log::error!("Metrics endpoint accept error: {}", err);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn handle_connection(mut stream: TcpStream) {
    // Read the request head. We only care about the request line, so stop at
    // the first \r\n\r\n and give up on anything oversized or too slow.
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_len = loop {
        if buf.len() > MAX_REQUEST_BYTES {
            write_simple_response(&mut stream, 400, "Bad Request", "request too large\n").await;
            return;
        }
        let read = tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut chunk)).await;
        let n = match read {
            Ok(Ok(n)) if n > 0 => n,
            _ => return, // timeout, error or EOF: drop the connection
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
    };

    let Ok(head) = std::str::from_utf8(&buf[..header_len]) else {
        write_simple_response(&mut stream, 400, "Bad Request", "malformed request\n").await;
        return;
    };

    let Some(request_line) = head.lines().next() else {
        write_simple_response(&mut stream, 400, "Bad Request", "empty request\n").await;
        return;
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    // Strip any query string before comparing paths
    let path = path.split('?').next().unwrap_or(path);

    match (method, path) {
        ("GET", "/metrics") | ("HEAD", "/metrics") => {
            let body = metrics().render();
            write_metrics_response(&mut stream, &body, method == "HEAD").await;
        }
        ("GET", _) | ("HEAD", _) => {
            write_simple_response(&mut stream, 404, "Not Found", "not found\n").await;
        }
        _ => {
            write_simple_response(
                &mut stream,
                405,
                "Method Not Allowed",
                "method not allowed\n",
            )
            .await;
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    }
}

async fn write_simple_response(stream: &mut TcpStream, code: u16, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

async fn write_metrics_response(stream: &mut TcpStream, body: &str, head_only: bool) {
    let mut response = format!(
        "HTTP/1.1 200 {}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_text(200),
        body.len()
    );
    if !head_only {
        response.push_str(body);
    }
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

fn push_family_header(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

fn push_module_family(
    out: &mut String,
    name: &str,
    help: &str,
    kind: &str,
    modules: &[(&str, &ModuleMetrics); 4],
    value: impl Fn(&ModuleMetrics) -> u64,
) {
    push_family_header(out, name, help, kind);
    for (module, m) in modules {
        out.push_str(name);
        out.push_str("{module=\"");
        out.push_str(module);
        out.push_str("\"} ");
        out.push_str(&value(m).to_string());
        out.push('\n');
    }
}

fn push_scalar_family(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    push_family_header(out, name, help, kind);
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_defaults_to_loopback_interfaces() {
        let settings = MetricsConfig::default().resolve(true);
        assert!(settings.enabled);
        assert_eq!(settings.interfaces, DEFAULT_METRICS_INTERFACES.to_vec());

        let settings = MetricsConfig::default().resolve(false);
        assert!(!settings.enabled);
        assert_eq!(settings.interfaces, DEFAULT_METRICS_INTERFACES.to_vec());
    }

    #[test]
    fn config_parses_toml_section() {
        let config: MetricsConfig = toml::from_str(
            r#"
            enabled = true
            interfaces = ["0.0.0.0:9154"]
        "#,
        )
        .unwrap();
        let settings = config.resolve(true);
        assert!(settings.enabled);
        assert_eq!(
            settings.interfaces,
            vec!["0.0.0.0:9154".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn counters_render_in_prometheus_format() {
        let m = metrics();

        // Compare counter deltas across renders instead of absolute values:
        // the registry is global and other tests may have counted already.
        m.record_auth(Module::Ssh, true);
        m.record_auth(Module::Mysql, false);
        m.record_command(Module::Mssql);
        m.record_session_start(Module::Ssh);
        m.record_session_end(Module::Ssh);
        m.record_connection(Module::Ssh);
        m.record_file_upload(1234);
        m.record_db_message();
        m.record_db_error();
        m.set_db_handler_live(true);

        let out = m.render();

        // Family headers
        assert!(out.contains("# TYPE honeypot_connections_total counter"));
        assert!(out.contains("# TYPE honeypot_auth_attempts_total counter"));
        assert!(out.contains("# TYPE honeypot_auth_success_total counter"));
        assert!(out.contains("# TYPE honeypot_auth_failure_total counter"));
        assert!(out.contains("# TYPE honeypot_commands_total counter"));
        assert!(out.contains("# TYPE honeypot_sessions_started_total counter"));
        assert!(out.contains("# TYPE honeypot_sessions_ended_total counter"));
        assert!(out.contains("# TYPE honeypot_sessions_active gauge"));
        assert!(out.contains("# TYPE honeypot_file_uploads_total counter"));
        assert!(out.contains("# TYPE honeypot_file_upload_bytes_total counter"));
        assert!(out.contains("# TYPE honeypot_db_messages_total counter"));
        assert!(out.contains("# TYPE honeypot_db_errors_total counter"));
        assert!(out.contains("# TYPE honeypot_db_handler_live gauge"));
        assert!(out.contains("# TYPE honeypot_uptime_seconds gauge"));

        // Sample lines exist for every module
        assert!(out.contains("honeypot_connections_total{module=\"ssh\"} "));
        assert!(out.contains("honeypot_connections_total{module=\"mysql\"} "));
        assert!(out.contains("honeypot_connections_total{module=\"mssql\"} "));
        assert!(out.contains("honeypot_auth_success_total{module=\"ssh\"} "));
        assert!(out.contains("honeypot_auth_failure_total{module=\"mysql\"} "));

        // Scalar gauges/values
        assert!(out.contains("honeypot_db_handler_live 1"));
        assert!(out.contains("honeypot_file_upload_bytes_total "));
        assert!(!out.contains("NaN"));

        // Exact delta check on a counter
        let sample_value = |out: &str| -> u64 {
            out.lines()
                .find(|l| l.starts_with("honeypot_commands_total{module=\"mssql\"} "))
                .unwrap()
                .rsplit(' ')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        };
        let before = sample_value(&out);
        m.record_command(Module::Mssql);
        assert_eq!(sample_value(&m.render()), before + 1);

        // Gauge decrements saturate instead of wrapping
        for _ in 0..3 {
            m.record_session_end(Module::Mssql);
        }
        let out = m.render();
        let active = out
            .lines()
            .find(|l| l.starts_with("honeypot_sessions_active{module=\"mssql\"} "))
            .unwrap()
            .rsplit(' ')
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(active, 0);
        m.set_db_handler_live(false);
    }

    #[tokio::test]
    async fn endpoint_serves_metrics_and_404() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let addr = std_listener.local_addr().unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();
        let server = tokio::spawn(MetricsServer.run_on_listener(listener));

        // GET /metrics returns 200 with the rendered registry
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            response.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
            "{response}"
        );
        assert!(response.contains("honeypot_uptime_seconds"), "{response}");

        // Unknown path returns 404
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /nope HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 404 Not Found"), "{response}");

        // HEAD /metrics returns headers only
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"HEAD /metrics HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        let header_end = response.find("\r\n\r\n").unwrap() + 4;
        assert_eq!(response.len(), header_end);

        server.abort();
        let _ = server.await;
    }
}
