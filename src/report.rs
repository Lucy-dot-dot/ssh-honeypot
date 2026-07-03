use chrono::{DateTime, Utc};
use clap::ValueEnum;
use minijinja::Environment;
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct ConnTrackRecord {
    pub timestamp: DateTime<Utc>,
    pub port: Option<i32>,
    pub local_port: Option<i32>,
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub struct AuthPasswordEnrichedRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub username: String,
    pub password: Option<String>,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub region_name: Option<String>,
    pub city: Option<String>,
    pub zip: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub as_info: Option<String>,
    pub abuse_confidence_score: Option<i16>,
    pub is_tor: Option<bool>,
    pub is_whitelisted: Option<bool>,
    pub total_reports: Option<i32>,
    pub abuse_check_timestamp: Option<DateTime<Utc>>,
    pub ipapi_check_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct PasswordReportData {
    pub total_attempts: i64,
    pub unique_ips: i64,
    pub unique_usernames: i64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub top_usernames: Vec<(String, i64)>,
    pub top_ips: Vec<(String, i64)>,
    pub all_usernames: Vec<(String, i64)>,
    pub all_ips: Vec<(String, i64)>,
}

pub struct ReportGenerator {
    pool: PgPool,
}

#[derive(Serialize)]
struct ConnRow {
    timestamp: String,
    port: String,
    local_port: String,
}

#[derive(Serialize)]
struct CountRow {
    rank: usize,
    value: String,
    count: i64,
}

#[derive(Serialize)]
struct RecentRow {
    timestamp: String,
    username: String,
    password: Option<String>,
}

#[derive(Serialize)]
struct DetailRow {
    timestamp: String,
    username: String,
    password: Option<String>,
    country: String,
    city: String,
    isp: String,
    abuse_score: String,
    is_tor: String,
    total_reports: String,
}

#[derive(Serialize)]
struct IpReportContext {
    ip: String,
    extended_info: bool,
    has_data: bool,
    has_conn: bool,
    conn_total: usize,
    conn_first: Option<String>,
    conn_last: Option<String>,
    conn_ports: Vec<i32>,
    conn_recent: Vec<ConnRow>,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    coordinates: Option<String>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    as_info: Option<String>,
    has_threat: bool,
    abuse_score: Option<i16>,
    threat_class: Option<String>,
    abuse_timestamp: String,
    is_tor: Option<bool>,
    total_reports: Option<i32>,
    total_attempts: usize,
    unique_usernames: usize,
    unique_passwords: usize,
    first_seen: Option<String>,
    last_seen: Option<String>,
    attack_duration_hours: Option<i64>,
    top_usernames: Vec<CountRow>,
    top_passwords: Vec<CountRow>,
    recent_attempts: Vec<RecentRow>,
    all_attempts: Vec<DetailRow>,
    generated_at: String,
}

#[derive(Serialize)]
struct PasswordReportContext {
    password: String,
    generated_at: String,
    total_attempts: i64,
    unique_ips: i64,
    unique_usernames: i64,
    first_seen: String,
    last_seen: String,
    top_usernames: Vec<CountRow>,
    top_ips: Vec<CountRow>,
    all_usernames: Vec<CountRow>,
    all_ips: Vec<CountRow>,
}

/// Lazily-built, shared minijinja environment holding the report templates.
///
/// Templates are embedded with `include_str!` so the environment is `'static`.
/// `trim_blocks` + `lstrip_blocks` are enabled so block tags (`{% ... %}`) do
/// not leave stray blank lines, which keeps the whitespace-sensitive text and
/// markdown output clean.
fn report_env() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Environment::new();
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.add_filter("fmt", format_datetime);
        env.add_template("ip_report.txt", include_str!("../templates/ip_report.txt"))
            .expect("ip_report.txt template is valid");
        env.add_template("ip_report.html", include_str!("../templates/ip_report.html"))
            .expect("ip_report.html template is valid");
        env.add_template("ip_report.md", include_str!("../templates/ip_report.md"))
            .expect("ip_report.md template is valid");
        env.add_template(
            "password_report.txt",
            include_str!("../templates/password_report.txt"),
        )
        .expect("password_report.txt template is valid");
        env.add_template(
            "password_report.html",
            include_str!("../templates/password_report.html"),
        )
        .expect("password_report.html template is valid");
        env.add_template(
            "password_report.md",
            include_str!("../templates/password_report.md"),
        )
        .expect("password_report.md template is valid");
        env
    })
}

/// minijinja filter that formats an RFC 3339 timestamp using a chrono format
/// string. Used in templates as `{{ ts | fmt("%Y-%m-%d %H:%M:%S UTC") }}`.
fn format_datetime(value: String, fmt: String) -> String {
    DateTime::parse_from_rfc3339(&value)
        .map(|dt| dt.format(&fmt).to_string())
        .unwrap_or_else(|_| value)
}

#[allow(unused)]
impl ReportGenerator {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_ip_isp_org(&self, ip: &str) -> Result<(Option<String>, Option<String>), sqlx::Error> {
        let row = sqlx::query(
            "SELECT isp, org FROM auth_password_enriched WHERE ip = $1::inet AND (isp IS NOT NULL OR org IS NOT NULL) ORDER BY timestamp DESC LIMIT 1"
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map_or((None, None), |r| (r.get("isp"), r.get("org"))))
    }

    /// Generate a report for an IP address.
    ///
    /// `extended_info` controls whether the geolocation, network and threat
    /// intelligence sections are included in the **text** report (they are
    /// always present in the HTML and markdown reports).
    pub async fn generate_ip_report(
        &self,
        ip: &str,
        format: &ReportFormat,
        extended_info: bool,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let records = self.get_auth_data_for_ip(ip).await?;
        let conn_track = self.get_conn_track_for_ip(ip).await?;

        if records.is_empty() && conn_track.is_empty() {
            return Ok(format!("No data found for IP address: {}", ip));
        }

        match format {
            ReportFormat::Text => {
                self.generate_text_report(ip, &records, &conn_track, extended_info)
            }
            ReportFormat::Html => self.generate_html_report(ip, &records, &conn_track),
            ReportFormat::Markdown => self.generate_markdown_report(ip, &records, &conn_track),
        }
    }

    async fn get_conn_track_for_ip(&self, ip: &str) -> Result<Vec<ConnTrackRecord>, sqlx::Error> {
        let query = "SELECT timestamp, port, local_port FROM conn_track WHERE ip = $1::inet ORDER BY timestamp DESC";

        let rows = sqlx::query(query)
            .bind(ip)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.iter().map(|row| ConnTrackRecord {
            timestamp: row.get("timestamp"),
            port: row.get("port"),
            local_port: row.get("local_port"),
        }).collect())
    }

    async fn get_auth_data_for_ip(&self, ip: &str) -> Result<Vec<AuthPasswordEnrichedRecord>, sqlx::Error> {
        let query = "SELECT
            id, timestamp, ip::text as ip_text, username, password,
            country_code, country, region, region_name, city, zip,
            lat, lon, timezone, isp, org, as_info,
            abuse_confidence_score, is_tor, is_whitelisted, total_reports,
            abuse_check_timestamp, ipapi_check_timestamp
            FROM auth_password_enriched WHERE ip = $1::inet ORDER BY timestamp DESC";

        let rows = sqlx::query(query)
            .bind(ip)
            .fetch_all(&self.pool)
            .await?;

        let mut records = Vec::new();
        for row in rows {
            records.push(AuthPasswordEnrichedRecord {
                id: row.get::<sqlx::types::Uuid, _>("id").to_string(),
                timestamp: row.get("timestamp"),
                ip: row.get::<String, _>("ip_text"),
                username: row.get("username"),
                password: row.get("password"),
                country_code: row.get("country_code"),
                country: row.get("country"),
                region: row.get("region"),
                region_name: row.get("region_name"),
                city: row.get("city"),
                zip: row.get("zip"),
                lat: row.get("lat"),
                lon: row.get("lon"),
                timezone: row.get("timezone"),
                isp: row.get("isp"),
                org: row.get("org"),
                as_info: row.get("as_info"),
                abuse_confidence_score: row.get("abuse_confidence_score"),
                is_tor: row.get("is_tor"),
                is_whitelisted: row.get("is_whitelisted"),
                total_reports: row.get("total_reports"),
                abuse_check_timestamp: row.get("abuse_check_timestamp"),
                ipapi_check_timestamp: row.get("ipapi_check_timestamp"),
            });
        }

        Ok(records)
    }

    fn build_ip_context(
        &self,
        ip: &str,
        records: &[AuthPasswordEnrichedRecord],
        conn_track: &[ConnTrackRecord],
        extended_info: bool,
    ) -> IpReportContext {
        let has_data = !records.is_empty();
        let has_conn = !conn_track.is_empty();

        let (
            country,
            country_code,
            region,
            city,
            coordinates,
            timezone,
            isp,
            org,
            as_info,
            abuse_score,
            abuse_timestamp,
            is_tor,
            total_reports,
            threat_class,
            has_threat,
        ) = if let Some(f) = records.first() {
            let coordinates = match (f.lat, f.lon) {
                (Some(lat), Some(lon)) => Some(format!("{:.4}, {:.4}", lat, lon)),
                _ => None,
            };
            let abuse_timestamp = f
                .abuse_check_timestamp
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let (abuse_score, threat_class, has_threat) = match f.abuse_confidence_score {
                Some(s) => {
                    let class = if s >= 75 {
                        "threat-high"
                    } else if s >= 25 {
                        "threat-medium"
                    } else {
                        "threat-low"
                    };
                    (Some(s), Some(class.to_string()), true)
                }
                None => (None, None, false),
            };
            (
                f.country.clone(),
                f.country_code.clone(),
                f.region_name.clone(),
                f.city.clone(),
                coordinates,
                f.timezone.clone(),
                f.isp.clone(),
                f.org.clone(),
                f.as_info.clone(),
                abuse_score,
                abuse_timestamp,
                f.is_tor,
                f.total_reports,
                threat_class,
                has_threat,
            )
        } else {
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                "Unknown".to_string(),
                None,
                None,
                None,
                false,
            )
        };

        let unique_usernames = records
            .iter()
            .map(|r| &r.username)
            .collect::<HashSet<_>>()
            .len();
        let unique_passwords = records
            .iter()
            .filter_map(|r| r.password.as_ref())
            .collect::<HashSet<_>>()
            .len();

        // records are ordered DESC: first() is newest, last() is oldest.
        let (first_seen, last_seen, attack_duration_hours) =
            if let (Some(oldest), Some(newest)) = (records.last(), records.first()) {
                let duration = newest
                    .timestamp
                    .signed_duration_since(oldest.timestamp)
                    .num_hours();
                (
                    Some(oldest.timestamp.to_rfc3339()),
                    Some(newest.timestamp.to_rfc3339()),
                    Some(duration),
                )
            } else {
                (None, None, None)
            };

        let top_usernames = count_top(records.iter().map(|r| r.username.clone()), 10);
        let top_passwords = count_top(records.iter().filter_map(|r| r.password.clone()), 10);

        let recent_attempts = records
            .iter()
            .take(20)
            .map(|r| RecentRow {
                timestamp: r.timestamp.to_rfc3339(),
                username: r.username.clone(),
                password: r.password.clone(),
            })
            .collect();

        let all_attempts = records
            .iter()
            .map(|r| DetailRow {
                timestamp: r.timestamp.to_rfc3339(),
                username: r.username.clone(),
                password: r.password.clone(),
                country: r.country.clone().unwrap_or_else(|| "-".to_string()),
                city: r.city.clone().unwrap_or_else(|| "-".to_string()),
                isp: r.isp.clone().unwrap_or_else(|| "-".to_string()),
                abuse_score: r
                    .abuse_confidence_score
                    .map(|s| format!("{}%", s))
                    .unwrap_or_else(|| "-".to_string()),
                is_tor: r
                    .is_tor
                    .map(|t| if t { "Yes".to_string() } else { "No".to_string() })
                    .unwrap_or_else(|| "-".to_string()),
                total_reports: r
                    .total_reports
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            })
            .collect();

        let (conn_first, conn_last) = if has_conn {
            (
                conn_track.last().map(|c| c.timestamp.to_rfc3339()),
                conn_track.first().map(|c| c.timestamp.to_rfc3339()),
            )
        } else {
            (None, None)
        };
        let mut conn_ports: Vec<i32> = conn_track
            .iter()
            .filter_map(|c| c.local_port)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        conn_ports.sort_unstable();
        let conn_recent = conn_track
            .iter()
            .take(20)
            .map(|c| ConnRow {
                timestamp: c.timestamp.to_rfc3339(),
                port: c
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                local_port: c
                    .local_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            })
            .collect();

        IpReportContext {
            ip: ip.to_string(),
            extended_info,
            has_data,
            has_conn,
            conn_total: conn_track.len(),
            conn_first,
            conn_last,
            conn_ports,
            conn_recent,
            country,
            country_code,
            region,
            city,
            coordinates,
            timezone,
            isp,
            org,
            as_info,
            has_threat,
            abuse_score,
            threat_class,
            abuse_timestamp,
            is_tor,
            total_reports,
            total_attempts: records.len(),
            unique_usernames,
            unique_passwords,
            first_seen,
            last_seen,
            attack_duration_hours,
            top_usernames,
            top_passwords,
            recent_attempts,
            all_attempts,
            generated_at: Utc::now().to_rfc3339(),
        }
    }

    fn generate_text_report(
        &self,
        ip: &str,
        records: &[AuthPasswordEnrichedRecord],
        conn_track: &[ConnTrackRecord],
        extended_info: bool,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = self.build_ip_context(ip, records, conn_track, extended_info);
        Ok(report_env().get_template("ip_report.txt")?.render(ctx)?)
    }

    fn generate_html_report(
        &self,
        ip: &str,
        records: &[AuthPasswordEnrichedRecord],
        conn_track: &[ConnTrackRecord],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = self.build_ip_context(ip, records, conn_track, false);
        Ok(report_env().get_template("ip_report.html")?.render(ctx)?)
    }

    fn generate_markdown_report(
        &self,
        ip: &str,
        records: &[AuthPasswordEnrichedRecord],
        conn_track: &[ConnTrackRecord],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = self.build_ip_context(ip, records, conn_track, false);
        Ok(report_env().get_template("ip_report.md")?.render(ctx)?)
    }

    pub async fn generate_password_report(
        &self,
        password: &str,
        format: &ReportFormat,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let data = self.get_password_data(password).await?;

        if data.total_attempts == 0 {
            return Ok(format!("No data found for password: {}", password));
        }

        match format {
            ReportFormat::Text => self.generate_password_text_report(password, &data),
            ReportFormat::Html => self.generate_password_html_report(password, &data),
            ReportFormat::Markdown => self.generate_password_markdown_report(password, &data),
        }
    }

    async fn get_password_data(&self, password: &str) -> Result<PasswordReportData, sqlx::Error> {
        let stats_query = "SELECT
            COUNT(*) as total_attempts,
            COUNT(DISTINCT ip) as unique_ips,
            COUNT(DISTINCT username) as unique_usernames,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
            FROM auth_password_enriched
            WHERE password = $1";

        let stats_row = sqlx::query(stats_query)
            .bind(password)
            .fetch_one(&self.pool)
            .await?;

        let total_attempts: i64 = stats_row.get("total_attempts");
        let unique_ips: i64 = stats_row.get("unique_ips");
        let unique_usernames: i64 = stats_row.get("unique_usernames");
        let first_seen: DateTime<Utc> = stats_row.get("first_seen");
        let last_seen: DateTime<Utc> = stats_row.get("last_seen");

        let username_query = "SELECT username, COUNT(*) as count
            FROM auth_password_enriched
            WHERE password = $1
            GROUP BY username
            ORDER BY count DESC
            LIMIT 10";

        let username_rows = sqlx::query(username_query)
            .bind(password)
            .fetch_all(&self.pool)
            .await?;

        let top_usernames: Vec<(String, i64)> = username_rows
            .iter()
            .map(|row| (row.get::<String, _>("username"), row.get::<i64, _>("count")))
            .collect();

        let ip_query = "SELECT ip::text as ip_text, COUNT(*) as count
            FROM auth_password_enriched
            WHERE password = $1
            GROUP BY ip
            ORDER BY count DESC
            LIMIT 10";

        let ip_rows = sqlx::query(ip_query)
            .bind(password)
            .fetch_all(&self.pool)
            .await?;

        let top_ips: Vec<(String, i64)> = ip_rows
            .iter()
            .map(|row| (row.get::<String, _>("ip_text"), row.get::<i64, _>("count")))
            // Formatter doing weird things with ip here. Appends /32 everywhere
            .map(|(ip, count)| (ip.replace("/32", ""), count))
            .collect();

        let all_username_query = "SELECT username, COUNT(*) as count
            FROM auth_password_enriched
            WHERE password = $1
            GROUP BY username
            ORDER BY count DESC";

        let all_username_rows = sqlx::query(all_username_query)
            .bind(password)
            .fetch_all(&self.pool)
            .await?;

        let all_usernames: Vec<(String, i64)> = all_username_rows
            .iter()
            .map(|row| (row.get::<String, _>("username"), row.get::<i64, _>("count")))
            .collect();

        let all_ip_query = "SELECT ip::text as ip_text, COUNT(*) as count
            FROM auth_password_enriched
            WHERE password = $1
            GROUP BY ip
            ORDER BY count DESC";

        let all_ip_rows = sqlx::query(all_ip_query)
            .bind(password)
            .fetch_all(&self.pool)
            .await?;

        let all_ips: Vec<(String, i64)> = all_ip_rows
            .iter()
            .map(|row| (row.get::<String, _>("ip_text"), row.get::<i64, _>("count")))
            // Formatter doing weird things with ip here. Appends /32 everywhere
            .map(|(ip, count)| (ip.replace("/32", ""), count))
            .collect();

        Ok(PasswordReportData {
            total_attempts,
            unique_ips,
            unique_usernames,
            first_seen,
            last_seen,
            top_usernames,
            top_ips,
            all_usernames,
            all_ips,
        })
    }

    fn build_password_context(
        &self,
        password: &str,
        data: &PasswordReportData,
    ) -> PasswordReportContext {
        fn to_rows(list: &[(String, i64)]) -> Vec<CountRow> {
            list.iter()
                .enumerate()
                .map(|(i, (value, count))| CountRow {
                    rank: i + 1,
                    value: value.clone(),
                    count: *count,
                })
                .collect()
        }

        PasswordReportContext {
            password: password.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            total_attempts: data.total_attempts,
            unique_ips: data.unique_ips,
            unique_usernames: data.unique_usernames,
            first_seen: data.first_seen.to_rfc3339(),
            last_seen: data.last_seen.to_rfc3339(),
            top_usernames: to_rows(&data.top_usernames),
            top_ips: to_rows(&data.top_ips),
            all_usernames: to_rows(&data.all_usernames),
            all_ips: to_rows(&data.all_ips),
        }
    }

    fn generate_password_text_report(
        &self,
        password: &str,
        data: &PasswordReportData,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = self.build_password_context(password, data);
        Ok(report_env()
            .get_template("password_report.txt")?
            .render(ctx)?)
    }

    fn generate_password_html_report(
        &self,
        password: &str,
        data: &PasswordReportData,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = self.build_password_context(password, data);
        Ok(report_env()
            .get_template("password_report.html")?
            .render(ctx)?)
    }

    fn generate_password_markdown_report(
        &self,
        password: &str,
        data: &PasswordReportData,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = self.build_password_context(password, data);
        Ok(report_env()
            .get_template("password_report.md")?
            .render(ctx)?)
    }
}

/// Counts occurrences of each key and returns the top `n` as ranked rows,
/// sorted by count descending with a stable alphabetical tiebreak.
fn count_top<S, I>(iter: I, n: usize) -> Vec<CountRow>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    let mut counts: HashMap<String, i64> = HashMap::new();
    for key in iter {
        *counts.entry(key.as_ref().to_string()).or_insert(0) += 1;
    }
    let mut entries: Vec<(String, i64)> = counts.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries
        .into_iter()
        .take(n)
        .enumerate()
        .map(|(i, (value, count))| CountRow {
            rank: i + 1,
            value,
            count,
        })
        .collect()
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ReportFormat {
    Text,
    Html,
    Markdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ip_context(extended_info: bool, has_data: bool) -> IpReportContext {
        IpReportContext {
            ip: "203.0.113.5".to_string(),
            extended_info,
            has_data,
            has_conn: true,
            conn_total: 3,
            conn_first: Some("2024-01-01T00:00:00+00:00".to_string()),
            conn_last: Some("2024-01-02T00:00:00+00:00".to_string()),
            conn_ports: vec![2222],
            conn_recent: vec![ConnRow {
                timestamp: "2024-01-02T00:00:00+00:00".to_string(),
                port: "54321".to_string(),
                local_port: "2222".to_string(),
            }],
            country: Some("Exampleland".to_string()),
            country_code: Some("EX".to_string()),
            region: Some("Region".to_string()),
            city: Some("City".to_string()),
            coordinates: Some("1.2345, 6.7890".to_string()),
            timezone: Some("UTC".to_string()),
            isp: Some("Example ISP".to_string()),
            org: Some("Example Org".to_string()),
            as_info: Some("AS64500 Example AS".to_string()),
            has_threat: true,
            abuse_score: Some(80),
            threat_class: Some("threat-high".to_string()),
            abuse_timestamp: "2024-01-02 12:00:00 UTC".to_string(),
            is_tor: Some(false),
            total_reports: Some(42),
            total_attempts: 2,
            unique_usernames: 2,
            unique_passwords: 1,
            first_seen: Some("2024-01-01T00:00:00+00:00".to_string()),
            last_seen: Some("2024-01-02T00:00:00+00:00".to_string()),
            attack_duration_hours: Some(24),
            top_usernames: vec![CountRow {
                rank: 1,
                value: "root".to_string(),
                count: 1,
            }],
            top_passwords: vec![CountRow {
                rank: 1,
                value: "hunter2".to_string(),
                count: 1,
            }],
            recent_attempts: vec![
                RecentRow {
                    timestamp: "2024-01-02T00:00:00+00:00".to_string(),
                    username: "root".to_string(),
                    password: Some("hunter2".to_string()),
                },
                RecentRow {
                    timestamp: "2024-01-01T00:00:00+00:00".to_string(),
                    username: "admin".to_string(),
                    password: None,
                },
            ],
            all_attempts: vec![DetailRow {
                timestamp: "2024-01-02T00:00:00+00:00".to_string(),
                username: "root".to_string(),
                password: Some("hunter2".to_string()),
                country: "Exampleland".to_string(),
                city: "City".to_string(),
                isp: "Example ISP".to_string(),
                abuse_score: "80%".to_string(),
                is_tor: "No".to_string(),
                total_reports: "42".to_string(),
            }],
            generated_at: "2024-01-03T00:00:00+00:00".to_string(),
        }
    }

    fn sample_password_context() -> PasswordReportContext {
        PasswordReportContext {
            password: "hunter2".to_string(),
            generated_at: "2024-01-03T00:00:00+00:00".to_string(),
            total_attempts: 5,
            unique_ips: 2,
            unique_usernames: 3,
            first_seen: "2024-01-01T00:00:00+00:00".to_string(),
            last_seen: "2024-01-02T00:00:00+00:00".to_string(),
            top_usernames: vec![CountRow {
                rank: 1,
                value: "root".to_string(),
                count: 3,
            }],
            top_ips: vec![CountRow {
                rank: 1,
                value: "203.0.113.5".to_string(),
                count: 4,
            }],
            all_usernames: vec![CountRow {
                rank: 1,
                value: "root".to_string(),
                count: 3,
            }],
            all_ips: vec![CountRow {
                rank: 1,
                value: "203.0.113.5".to_string(),
                count: 4,
            }],
        }
    }

    #[test]
    fn templates_parse_and_render_ip() {
        let env = report_env();
        for name in ["ip_report.txt", "ip_report.html", "ip_report.md"] {
            let tmpl = env.get_template(name).expect("template exists");
            // Full context with extended info enabled.
            let out = tmpl
                .render(sample_ip_context(true, true))
                .unwrap_or_else(|e| panic!("rendering {name} failed: {e}"));
            assert!(!out.is_empty(), "{name} produced empty output");
            // Minimal / no-data context.
            let out2 = tmpl
                .render(sample_ip_context(false, false))
                .unwrap_or_else(|e| panic!("rendering {name} (minimal) failed: {e}"));
            assert!(!out2.is_empty(), "{name} (minimal) produced empty output");
        }
    }

    #[test]
    fn templates_parse_and_render_password() {
        let env = report_env();
        for name in [
            "password_report.txt",
            "password_report.html",
            "password_report.md",
        ] {
            let tmpl = env.get_template(name).expect("template exists");
            let out = tmpl
                .render(sample_password_context())
                .unwrap_or_else(|e| panic!("rendering {name} failed: {e}"));
            assert!(!out.is_empty(), "{name} produced empty output");
        }
    }

    #[test]
    fn fmt_filter_formats_rfc3339() {
        assert_eq!(
            format_datetime("2024-01-02T03:04:05+00:00".to_string(), "%Y".to_string()),
            "2024"
        );
        // Invalid input is returned unchanged.
        assert_eq!(
            format_datetime("not-a-date".to_string(), "%Y".to_string()),
            "not-a-date"
        );
    }

    #[test]
    fn count_top_ranks_descending() {
        let rows = count_top(
            ["a", "b", "a", "c", "a", "b"]
                .into_iter()
                .map(String::from),
            2,
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].value, "a");
        assert_eq!(rows[0].count, 3);
        assert_eq!(rows[0].rank, 1);
        assert_eq!(rows[1].value, "b");
        assert_eq!(rows[1].count, 2);
    }
}
