use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::fmt::Write;
use clap::ValueEnum;

#[derive(Debug, Clone)]
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

pub struct ReportGenerator {
    pool: PgPool,
}

impl ReportGenerator {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn generate_ip_report(&self, ip: &str, format: &ReportFormat) -> Result<String, Box<dyn std::error::Error>> {
        let records = self.get_auth_data_for_ip(ip).await?;

        if records.is_empty() {
            return Ok(format!("No data found for IP address: {}", ip));
        }

        match format {
            ReportFormat::Text => self.generate_text_report(ip, &records),
            ReportFormat::Html => self.generate_html_report(ip, &records),
            ReportFormat::Markdown => self.generate_markdown_report(ip, &records),
        }
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

    fn generate_text_report(&self, ip: &str, records: &[AuthPasswordEnrichedRecord]) -> Result<String, Box<dyn std::error::Error>> {
        let mut report = String::new();

        writeln!(report, "==========================================")?;
        writeln!(report, "SSH HONEYPOT REPORT FOR IP: {}", ip)?;
        writeln!(report, "==========================================")?;
        writeln!(report)?;

        // Basic info from first record (should be same for all)
        if let Some(first_record) = records.first() {
            writeln!(report, "GEOLOCATION INFORMATION:")?;
            if let Some(country) = &first_record.country {
                writeln!(report, "  Country: {}", country)?;
            }
            if let Some(country_code) = &first_record.country_code {
                writeln!(report, "  Country Code: {}", country_code)?;
            }
            if let Some(region) = &first_record.region_name {
                writeln!(report, "  Region: {}", region)?;
            }
            if let Some(city) = &first_record.city {
                writeln!(report, "  City: {}", city)?;
            }
            if let (Some(lat), Some(lon)) = (first_record.lat, first_record.lon) {
                writeln!(report, "  Coordinates: {:.4}, {:.4}", lat, lon)?;
            }
            if let Some(timezone) = &first_record.timezone {
                writeln!(report, "  Timezone: {}", timezone)?;
            }
            writeln!(report)?;

            writeln!(report, "NETWORK INFORMATION:")?;
            if let Some(isp) = &first_record.isp {
                writeln!(report, "  ISP: {}", isp)?;
            }
            if let Some(org) = &first_record.org {
                writeln!(report, "  Organization: {}", org)?;
            }
            if let Some(as_info) = &first_record.as_info {
                writeln!(report, "  AS Info: {}", as_info)?;
            }
            writeln!(report)?;

            if let Some(abuse_score) = first_record.abuse_confidence_score {
                let timestamp = first_record.abuse_check_timestamp
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or("Unknown".to_string());

                writeln!(report, "THREAT INTELLIGENCE (from AbuseIPDB cached at: {}):", timestamp)?;
                writeln!(report, "  Abuse Confidence Score: {}%", abuse_score)?;
                if let Some(is_tor) = first_record.is_tor {
                    writeln!(report, "  Tor Exit Node: {}", if is_tor { "Yes" } else { "No" })?;
                }
                if let Some(total_reports) = first_record.total_reports {
                    writeln!(report, "  Total Abuse Reports: {}", total_reports)?;
                }
                writeln!(report)?;
            }
        }

        // Statistics
        writeln!(report, "ATTACK STATISTICS:")?;
        writeln!(report, "  Total Authentication Attempts: {}", records.len())?;

        let unique_usernames = records.iter()
            .map(|r| &r.username)
            .collect::<std::collections::HashSet<_>>()
            .len();
        writeln!(report, "  Unique Usernames Tried: {}", unique_usernames)?;

        let unique_passwords = records.iter()
            .filter_map(|r| r.password.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .len();
        writeln!(report, "  Unique Passwords Tried: {}", unique_passwords)?;

        if let (Some(first), Some(last)) = (records.last(), records.first()) {
            writeln!(report, "  First Seen: {}", first.timestamp.format("%Y-%m-%d %H:%M:%S UTC"))?;
            writeln!(report, "  Last Seen: {}", last.timestamp.format("%Y-%m-%d %H:%M:%S UTC"))?;
        }
        writeln!(report)?;

        // Top usernames
        let mut username_counts: HashMap<&String, usize> = HashMap::new();
        for record in records {
            *username_counts.entry(&record.username).or_insert(0) += 1;
        }
        let mut username_vec: Vec<_> = username_counts.into_iter().collect();
        username_vec.sort_by(|a, b| b.1.cmp(&a.1));

        writeln!(report, "TOP USERNAMES ATTEMPTED:")?;
        for (username, count) in username_vec.iter().take(10) {
            writeln!(report, "  {} ({}x)", username, count)?;
        }
        writeln!(report)?;

        // Top passwords
        let mut password_counts: HashMap<&String, usize> = HashMap::new();
        for record in records {
            if let Some(password) = &record.password {
                *password_counts.entry(password).or_insert(0) += 1;
            }
        }
        let mut password_vec: Vec<_> = password_counts.into_iter().collect();
        password_vec.sort_by(|a, b| b.1.cmp(&a.1));

        writeln!(report, "TOP PASSWORDS ATTEMPTED:")?;
        for (password, count) in password_vec.iter().take(10) {
            writeln!(report, "  {} ({}x)", password, count)?;
        }
        writeln!(report)?;

        // Recent attempts
        writeln!(report, "RECENT AUTHENTICATION ATTEMPTS:")?;
        for record in records.iter().take(20) {
            let password_display = record.password.as_deref().unwrap_or("<no password>");
            writeln!(report, "  {} | {} | {}",
                record.timestamp.format("%Y-%m-%d %H:%M:%S"),
                record.username,
                password_display)?;
        }

        writeln!(report)?;
        writeln!(report, "==========================================")?;

        Ok(report)
    }

    fn generate_html_report(&self, ip: &str, records: &[AuthPasswordEnrichedRecord]) -> Result<String, Box<dyn std::error::Error>> {
        let mut html = String::new();

        // HTML5 DOCTYPE and semantic structure
        writeln!(html, "<!DOCTYPE html>")?;
        writeln!(html, "<html lang=\"en\">")?;
        writeln!(html, "<head>")?;
        writeln!(html, "    <meta charset=\"UTF-8\">")?;
        writeln!(html, "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")?;
        writeln!(html, "    <title>SSH Honeypot Report - IP {}</title>", ip)?;
        writeln!(html, "    <style>")?;

        // Embedded CSS for styling and accessibility
        writeln!(html, r#"
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --danger-color: #e74c3c;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --background-color: #ecf0f1;
            --text-color: #2c3e50;
            --border-color: #bdc3c7;
            --table-header-bg: #34495e;
            --table-stripe-bg: #f8f9fa;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--background-color);
            margin: 0;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}

        header {{
            background: var(--primary-color);
            color: white;
            padding: 2rem;
            text-align: center;
        }}

        h1 {{
            margin: 0;
            font-size: 2rem;
            font-weight: 300;
        }}

        .ip-address {{
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: var(--warning-color);
        }}

        main {{
            padding: 2rem;
        }}

        section {{
            margin-bottom: 3rem;
        }}

        h2 {{
            color: var(--primary-color);
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
        }}

        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .info-card {{
            background: var(--table-stripe-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
        }}

        .info-label {{
            font-weight: bold;
            color: var(--primary-color);
            margin-bottom: 0.25rem;
        }}

        .info-value {{
            font-family: 'Courier New', monospace;
            word-break: break-all;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2rem;
            background: white;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}

        th {{
            background: var(--table-header-bg);
            color: white;
            font-weight: 600;
            padding: 1rem;
            text-align: left;
            border-bottom: 2px solid var(--border-color);
        }}

        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }}

        tbody tr:nth-child(even) {{
            background-color: var(--table-stripe-bg);
        }}

        tbody tr:hover {{
            background-color: #e8f4fd;
        }}

        .metric-value {{
            font-weight: bold;
            font-size: 1.1rem;
        }}

        .threat-high {{
            color: var(--danger-color);
            font-weight: bold;
        }}

        .threat-medium {{
            color: var(--warning-color);
            font-weight: bold;
        }}

        .threat-low {{
            color: var(--success-color);
        }}

        .tor-indicator {{
            background: var(--danger-color);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            font-size: 0.875rem;
            font-weight: bold;
        }}

        .code {{
            font-family: 'Courier New', monospace;
            background: var(--table-stripe-bg);
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            font-size: 0.9rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: linear-gradient(135deg, var(--secondary-color), #5dade2);
            color: white;
            padding: 1.5rem;
            border-radius: 6px;
            text-align: center;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
        }}

        .stat-number {{
            font-size: 2rem;
            font-weight: bold;
            display: block;
        }}

        .stat-label {{
            font-size: 0.875rem;
            opacity: 0.9;
            margin-top: 0.5rem;
        }}

        .no-data {{
            text-align: center;
            color: #7f8c8d;
            font-style: italic;
            padding: 2rem;
        }}

        footer {{
            background: var(--background-color);
            padding: 1rem 2rem;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.875rem;
            border-top: 1px solid var(--border-color);
        }}

        /* Details section styling */
        details {{
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin: 1rem 0;
            overflow: hidden;
        }}

        summary {{
            background: var(--table-stripe-bg);
            padding: 1rem;
            cursor: pointer;
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
            transition: background-color 0.2s ease;
        }}

        summary:hover {{
            background: #e9ecef;
        }}

        summary h2 {{
            margin: 0;
            display: inline;
            border: none;
            padding: 0;
            font-size: 1.25rem;
        }}

        .details-content {{
            padding: 1rem;
        }}

        .details-content table {{
            font-size: 0.875rem;
            margin-top: 1rem;
        }}

        .details-content th, .details-content td {{
            padding: 0.5rem;
            font-size: 0.875rem;
        }}

        /* Accessibility improvements */
        @media (prefers-reduced-motion: reduce) {{
            * {{
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }}
        }}

        /* Print styles */
        @media print {{
            body {{
                background: white;
                color: black;
            }}

            .container {{
                box-shadow: none;
                border: 1px solid #000;
            }}

            header {{
                background: #f0f0f0 !important;
                color: black !important;
            }}
        }}

        /* High contrast mode support */
        @media (prefers-contrast: high) {{
            :root {{
                --border-color: #000;
                --text-color: #000;
            }}
        }}

        /* Responsive design */
        @media (max-width: 768px) {{
            body {{
                padding: 10px;
            }}

            .container {{
                border-radius: 0;
            }}

            header {{
                padding: 1rem;
            }}

            h1 {{
                font-size: 1.5rem;
            }}

            main {{
                padding: 1rem;
            }}

            table {{
                font-size: 0.875rem;
            }}

            th, td {{
                padding: 0.5rem;
            }}
        }}
        "#)?;

        writeln!(html, "    </style>")?;
        writeln!(html, "</head>")?;
        writeln!(html, "<body>")?;
        writeln!(html, "    <div class=\"container\">")?;

        // Header
        writeln!(html, "        <header>")?;
        writeln!(html, "            <h1>SSH Honeypot Security Report</h1>")?;
        writeln!(html, "            <p>Analysis for IP Address: <span class=\"ip-address\">{}</span></p>", ip)?;
        writeln!(html, "        </header>")?;

        writeln!(html, "        <main>")?;

        if records.is_empty() {
            writeln!(html, "            <div class=\"no-data\">")?;
            writeln!(html, "                <h2>No Data Available</h2>")?;
            writeln!(html, "                <p>No authentication attempts found for this IP address.</p>")?;
            writeln!(html, "            </div>")?;
        } else {
            // Generate statistics first
            let unique_usernames = records.iter()
                .map(|r| &r.username)
                .collect::<std::collections::HashSet<_>>()
                .len();

            let unique_passwords = records.iter()
                .filter_map(|r| r.password.as_ref())
                .collect::<std::collections::HashSet<_>>()
                .len();

            // Statistics section
            writeln!(html, "            <section aria-labelledby=\"stats-heading\">")?;
            writeln!(html, "                <h2 id=\"stats-heading\">Attack Statistics</h2>")?;
            writeln!(html, "                <div class=\"stats-grid\">")?;
            writeln!(html, "                    <div class=\"stat-card\">")?;
            writeln!(html, "                        <span class=\"stat-number\">{}</span>", records.len())?;
            writeln!(html, "                        <div class=\"stat-label\">Total Attempts</div>")?;
            writeln!(html, "                    </div>")?;
            writeln!(html, "                    <div class=\"stat-card\">")?;
            writeln!(html, "                        <span class=\"stat-number\">{}</span>", unique_usernames)?;
            writeln!(html, "                        <div class=\"stat-label\">Unique Usernames</div>")?;
            writeln!(html, "                    </div>")?;
            writeln!(html, "                    <div class=\"stat-card\">")?;
            writeln!(html, "                        <span class=\"stat-number\">{}</span>", unique_passwords)?;
            writeln!(html, "                        <div class=\"stat-label\">Unique Passwords</div>")?;
            writeln!(html, "                    </div>")?;

            if let (Some(first), Some(last)) = (records.last(), records.first()) {
                let duration = last.timestamp.signed_duration_since(first.timestamp);
                let duration_hours = duration.num_hours();
                writeln!(html, "                    <div class=\"stat-card\">")?;
                writeln!(html, "                        <span class=\"stat-number\">{}</span>", duration_hours)?;
                writeln!(html, "                        <div class=\"stat-label\">Attack Duration (hours)</div>")?;
                writeln!(html, "                    </div>")?;
            }
            writeln!(html, "                </div>")?;
            writeln!(html, "            </section>")?;

            // Geolocation and Network Info
            if let Some(first_record) = records.first() {
                writeln!(html, "            <section aria-labelledby=\"geo-heading\">")?;
                writeln!(html, "                <h2 id=\"geo-heading\">Geolocation & Network Information</h2>")?;
                writeln!(html, "                <div class=\"info-grid\">")?;

                if let Some(country) = &first_record.country {
                    writeln!(html, "                    <div class=\"info-card\">")?;
                    writeln!(html, "                        <div class=\"info-label\">Country</div>")?;
                    writeln!(html, "                        <div class=\"info-value\">{}</div>", country)?;
                    writeln!(html, "                    </div>")?;
                }

                if let Some(region) = &first_record.region_name {
                    writeln!(html, "                    <div class=\"info-card\">")?;
                    writeln!(html, "                        <div class=\"info-label\">Region</div>")?;
                    writeln!(html, "                        <div class=\"info-value\">{}</div>", region)?;
                    writeln!(html, "                    </div>")?;
                }

                if let Some(city) = &first_record.city {
                    writeln!(html, "                    <div class=\"info-card\">")?;
                    writeln!(html, "                        <div class=\"info-label\">City</div>")?;
                    writeln!(html, "                        <div class=\"info-value\">{}</div>", city)?;
                    writeln!(html, "                    </div>")?;
                }

                if let Some(isp) = &first_record.isp {
                    writeln!(html, "                    <div class=\"info-card\">")?;
                    writeln!(html, "                        <div class=\"info-label\">Internet Service Provider</div>")?;
                    writeln!(html, "                        <div class=\"info-value\">{}</div>", isp)?;
                    writeln!(html, "                    </div>")?;
                }

                if let Some(org) = &first_record.org {
                    writeln!(html, "                    <div class=\"info-card\">")?;
                    writeln!(html, "                        <div class=\"info-label\">Organization</div>")?;
                    writeln!(html, "                        <div class=\"info-value\">{}</div>", org)?;
                    writeln!(html, "                    </div>")?;
                }

                if let Some(as_info) = &first_record.as_info {
                    writeln!(html, "                    <div class=\"info-card\">")?;
                    writeln!(html, "                        <div class=\"info-label\">AS Information</div>")?;
                    writeln!(html, "                        <div class=\"info-value\">{}</div>", as_info)?;
                    writeln!(html, "                    </div>")?;
                }

                writeln!(html, "                </div>")?;
                writeln!(html, "            </section>")?;

                // Threat Intelligence
                if let Some(abuse_score) = first_record.abuse_confidence_score {
                    let timestamp = first_record.abuse_check_timestamp
                        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or("Unknown".to_string());

                    writeln!(html, "            <section aria-labelledby=\"threat-heading\">")?;
                    writeln!(html, "                <h2 id=\"threat-heading\">Threat Intelligence</h2>")?;
                    writeln!(html, "                <p><em>Data from AbuseIPDB cached at: {}</em></p>", timestamp)?;
                    writeln!(html, "                <div class=\"info-grid\">")?;

                    let threat_class = if abuse_score >= 75 {
                        "threat-high"
                    } else if abuse_score >= 25 {
                        "threat-medium"
                    } else {
                        "threat-low"
                    };

                    writeln!(html, "                    <div class=\"info-card\">")?;
                    writeln!(html, "                        <div class=\"info-label\">Abuse Confidence Score</div>")?;
                    writeln!(html, "                        <div class=\"info-value\"><span class=\"{}\">{} %</span></div>", threat_class, abuse_score)?;
                    writeln!(html, "                    </div>")?;

                    if let Some(is_tor) = first_record.is_tor {
                        writeln!(html, "                    <div class=\"info-card\">")?;
                        writeln!(html, "                        <div class=\"info-label\">Tor Exit Node</div>")?;
                        if is_tor {
                            writeln!(html, "                        <div class=\"info-value\"><span class=\"tor-indicator\">YES</span></div>")?;
                        } else {
                            writeln!(html, "                        <div class=\"info-value\">No</div>")?;
                        }
                        writeln!(html, "                    </div>")?;
                    }

                    if let Some(total_reports) = first_record.total_reports {
                        writeln!(html, "                    <div class=\"info-card\">")?;
                        writeln!(html, "                        <div class=\"info-label\">Total Abuse Reports</div>")?;
                        writeln!(html, "                        <div class=\"info-value\">{}</div>", total_reports)?;
                        writeln!(html, "                    </div>")?;
                    }

                    writeln!(html, "                </div>")?;
                    writeln!(html, "            </section>")?;
                }
            }

            // Top Usernames
            let mut username_counts: HashMap<&String, usize> = HashMap::new();
            for record in records {
                *username_counts.entry(&record.username).or_insert(0) += 1;
            }
            let mut username_vec: Vec<_> = username_counts.into_iter().collect();
            username_vec.sort_by(|a, b| b.1.cmp(&a.1));

            writeln!(html, "            <section aria-labelledby=\"usernames-heading\">")?;
            writeln!(html, "                <h2 id=\"usernames-heading\">Top Usernames Attempted</h2>")?;
            writeln!(html, "                <table role=\"table\" aria-label=\"Top attempted usernames\">")?;
            writeln!(html, "                    <thead>")?;
            writeln!(html, "                        <tr>")?;
            writeln!(html, "                            <th scope=\"col\">Rank</th>")?;
            writeln!(html, "                            <th scope=\"col\">Username</th>")?;
            writeln!(html, "                            <th scope=\"col\">Attempts</th>")?;
            writeln!(html, "                        </tr>")?;
            writeln!(html, "                    </thead>")?;
            writeln!(html, "                    <tbody>")?;
            for (i, (username, count)) in username_vec.iter().take(10).enumerate() {
                writeln!(html, "                        <tr>")?;
                writeln!(html, "                            <td>{}</td>", i + 1)?;
                writeln!(html, "                            <td><span class=\"code\">{}</span></td>", username)?;
                writeln!(html, "                            <td><span class=\"metric-value\">{}</span></td>", count)?;
                writeln!(html, "                        </tr>")?;
            }
            writeln!(html, "                    </tbody>")?;
            writeln!(html, "                </table>")?;
            writeln!(html, "            </section>")?;

            // Top Passwords
            let mut password_counts: HashMap<&String, usize> = HashMap::new();
            for record in records {
                if let Some(password) = &record.password {
                    *password_counts.entry(password).or_insert(0) += 1;
                }
            }
            let mut password_vec: Vec<_> = password_counts.into_iter().collect();
            password_vec.sort_by(|a, b| b.1.cmp(&a.1));

            writeln!(html, "            <section aria-labelledby=\"passwords-heading\">")?;
            writeln!(html, "                <h2 id=\"passwords-heading\">Top Passwords Attempted</h2>")?;
            writeln!(html, "                <table role=\"table\" aria-label=\"Top attempted passwords\">")?;
            writeln!(html, "                    <thead>")?;
            writeln!(html, "                        <tr>")?;
            writeln!(html, "                            <th scope=\"col\">Rank</th>")?;
            writeln!(html, "                            <th scope=\"col\">Password</th>")?;
            writeln!(html, "                            <th scope=\"col\">Attempts</th>")?;
            writeln!(html, "                        </tr>")?;
            writeln!(html, "                    </thead>")?;
            writeln!(html, "                    <tbody>")?;
            for (i, (password, count)) in password_vec.iter().take(10).enumerate() {
                writeln!(html, "                        <tr>")?;
                writeln!(html, "                            <td>{}</td>", i + 1)?;
                writeln!(html, "                            <td><span class=\"code\">{}</span></td>", password)?;
                writeln!(html, "                            <td><span class=\"metric-value\">{}</span></td>", count)?;
                writeln!(html, "                        </tr>")?;
            }
            writeln!(html, "                    </tbody>")?;
            writeln!(html, "                </table>")?;
            writeln!(html, "            </section>")?;

            // Recent attempts
            writeln!(html, "            <section aria-labelledby=\"recent-heading\">")?;
            writeln!(html, "                <h2 id=\"recent-heading\">Recent Authentication Attempts</h2>")?;
            writeln!(html, "                <table role=\"table\" aria-label=\"Recent authentication attempts\">")?;
            writeln!(html, "                    <thead>")?;
            writeln!(html, "                        <tr>")?;
            writeln!(html, "                            <th scope=\"col\">Timestamp</th>")?;
            writeln!(html, "                            <th scope=\"col\">Username</th>")?;
            writeln!(html, "                            <th scope=\"col\">Password</th>")?;
            writeln!(html, "                        </tr>")?;
            writeln!(html, "                    </thead>")?;
            writeln!(html, "                    <tbody>")?;
            for record in records.iter().take(20) {
                let password_display = record.password.as_deref().unwrap_or("*no password*");
                writeln!(html, "                        <tr>")?;
                writeln!(html, "                            <td>{}</td>", record.timestamp.format("%Y-%m-%d %H:%M:%S"))?;
                writeln!(html, "                            <td><span class=\"code\">{}</span></td>", record.username)?;
                writeln!(html, "                            <td><span class=\"code\">{}</span></td>", password_display)?;
                writeln!(html, "                        </tr>")?;
            }
            writeln!(html, "                    </tbody>")?;
            writeln!(html, "                </table>")?;
            writeln!(html, "            </section>")?;

            // Detailed data section
            writeln!(html, "            <section aria-labelledby=\"details-heading\">")?;
            writeln!(html, "                <details>")?;
            writeln!(html, "                    <summary><h2 id=\"details-heading\">Complete Authentication Data</h2></summary>")?;
            writeln!(html, "                    <div class=\"details-content\">")?;
            writeln!(html, "                        <p><em>Complete detailed information for all authentication attempts from this IP address.</em></p>")?;
            writeln!(html, "                        <table role=\"table\" aria-label=\"Complete authentication data\">")?;
            writeln!(html, "                            <thead>")?;
            writeln!(html, "                                <tr>")?;
            writeln!(html, "                                    <th scope=\"col\">Timestamp</th>")?;
            writeln!(html, "                                    <th scope=\"col\">Username</th>")?;
            writeln!(html, "                                    <th scope=\"col\">Password</th>")?;
            writeln!(html, "                                    <th scope=\"col\">Country</th>")?;
            writeln!(html, "                                </tr>")?;
            writeln!(html, "                            </thead>")?;
            writeln!(html, "                            <tbody>")?;
            for record in records.iter() {
                let password_display = record.password.as_deref().unwrap_or("*no password*");
                let country_display = record.country.as_deref().unwrap_or("-");

                writeln!(html, "                                <tr>")?;
                writeln!(html, "                                    <td>{}</td>", record.timestamp.format("%Y-%m-%d %H:%M:%S"))?;
                writeln!(html, "                                    <td><span class=\"code\">{}</span></td>", record.username)?;
                writeln!(html, "                                    <td><span class=\"code\">{}</span></td>", password_display)?;
                writeln!(html, "                                    <td>{}</td>", country_display)?;
                writeln!(html, "                                </tr>")?;
            }
            writeln!(html, "                            </tbody>")?;
            writeln!(html, "                        </table>")?;
            writeln!(html, "                    </div>")?;
            writeln!(html, "                </details>")?;
            writeln!(html, "            </section>")?;
        }

        writeln!(html, "        </main>")?;

        writeln!(html, "        <footer>")?;
        writeln!(html, "            <p>Report generated by SSH Honeypot Report Generator on {}</p>", Utc::now().format("%Y-%m-%d %H:%M:%S UTC"))?;
        writeln!(html, "        </footer>")?;

        writeln!(html, "    </div>")?;
        writeln!(html, "</body>")?;
        writeln!(html, "</html>")?;

        Ok(html)
    }

    fn generate_markdown_report(&self, ip: &str, records: &[AuthPasswordEnrichedRecord]) -> Result<String, Box<dyn std::error::Error>> {
        let mut report = String::new();

        writeln!(report, "# SSH Honeypot Report for IP: {}", ip)?;
        writeln!(report)?;

        if records.is_empty() {
            writeln!(report, "**No data found for this IP address.**")?;
            return Ok(report);
        }

        // Basic info from first record (should be same for all)
        if let Some(first_record) = records.first() {
            writeln!(report, "## Geolocation Information")?;
            writeln!(report)?;

            let mut geo_table = Vec::new();
            if let Some(country) = &first_record.country {
                geo_table.push(format!("| Country | {} |", country));
            }
            if let Some(country_code) = &first_record.country_code {
                geo_table.push(format!("| Country Code | {} |", country_code));
            }
            if let Some(region) = &first_record.region_name {
                geo_table.push(format!("| Region | {} |", region));
            }
            if let Some(city) = &first_record.city {
                geo_table.push(format!("| City | {} |", city));
            }
            if let (Some(lat), Some(lon)) = (first_record.lat, first_record.lon) {
                geo_table.push(format!("| Coordinates | {:.4}, {:.4} |", lat, lon));
            }
            if let Some(timezone) = &first_record.timezone {
                geo_table.push(format!("| Timezone | {} |", timezone));
            }

            if !geo_table.is_empty() {
                writeln!(report, "| Field | Value |")?;
                writeln!(report, "|-------|-------|")?;
                for row in geo_table {
                    writeln!(report, "{}", row)?;
                }
                writeln!(report)?;
            }

            writeln!(report, "## Network Information")?;
            writeln!(report)?;

            let mut network_table = Vec::new();
            if let Some(isp) = &first_record.isp {
                network_table.push(format!("| ISP | {} |", isp));
            }
            if let Some(org) = &first_record.org {
                network_table.push(format!("| Organization | {} |", org));
            }
            if let Some(as_info) = &first_record.as_info {
                network_table.push(format!("| AS Info | {} |", as_info));
            }

            if !network_table.is_empty() {
                writeln!(report, "| Field | Value |")?;
                writeln!(report, "|-------|-------|")?;
                for row in network_table {
                    writeln!(report, "{}", row)?;
                }
                writeln!(report)?;
            }

            if let Some(abuse_score) = first_record.abuse_confidence_score {
                let timestamp = first_record.abuse_check_timestamp
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or("Unknown".to_string());

                writeln!(report, "## Threat Intelligence")?;
                writeln!(report)?;
                writeln!(report, "*Data from AbuseIPDB cached at: {}*", timestamp)?;
                writeln!(report)?;

                writeln!(report, "| Field | Value |")?;
                writeln!(report, "|-------|-------|")?;
                writeln!(report, "| Abuse Confidence Score | **{}%** |", abuse_score)?;

                if let Some(is_tor) = first_record.is_tor {
                    let tor_status = if is_tor { "**Yes**" } else { "No" };
                    writeln!(report, "| Tor Exit Node | {} |", tor_status)?;
                }

                if let Some(total_reports) = first_record.total_reports {
                    writeln!(report, "| Total Abuse Reports | {} |", total_reports)?;
                }
                writeln!(report)?;
            }
        }

        // Statistics
        writeln!(report, "## Attack Statistics")?;
        writeln!(report)?;

        let unique_usernames = records.iter()
            .map(|r| &r.username)
            .collect::<std::collections::HashSet<_>>()
            .len();

        let unique_passwords = records.iter()
            .filter_map(|r| r.password.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .len();

        writeln!(report, "| Metric | Count |")?;
        writeln!(report, "|--------|-------|")?;
        writeln!(report, "| Total Authentication Attempts | **{}** |", records.len())?;
        writeln!(report, "| Unique Usernames Tried | {} |", unique_usernames)?;
        writeln!(report, "| Unique Passwords Tried | {} |", unique_passwords)?;

        if let (Some(first), Some(last)) = (records.last(), records.first()) {
            writeln!(report, "| First Seen | {} |", first.timestamp.format("%Y-%m-%d %H:%M:%S UTC"))?;
            writeln!(report, "| Last Seen | {} |", last.timestamp.format("%Y-%m-%d %H:%M:%S UTC"))?;
        }
        writeln!(report)?;

        // Top usernames
        let mut username_counts: HashMap<&String, usize> = HashMap::new();
        for record in records {
            *username_counts.entry(&record.username).or_insert(0) += 1;
        }
        let mut username_vec: Vec<_> = username_counts.into_iter().collect();
        username_vec.sort_by(|a, b| b.1.cmp(&a.1));

        writeln!(report, "## Top Usernames Attempted")?;
        writeln!(report)?;
        writeln!(report, "| Rank | Username | Attempts |")?;
        writeln!(report, "|------|----------|----------|")?;
        for (i, (username, count)) in username_vec.iter().take(10).enumerate() {
            writeln!(report, "| {} | `{}` | {} |", i + 1, username, count)?;
        }
        writeln!(report)?;

        // Top passwords
        let mut password_counts: HashMap<&String, usize> = HashMap::new();
        for record in records {
            if let Some(password) = &record.password {
                *password_counts.entry(password).or_insert(0) += 1;
            }
        }
        let mut password_vec: Vec<_> = password_counts.into_iter().collect();
        password_vec.sort_by(|a, b| b.1.cmp(&a.1));

        writeln!(report, "## Top Passwords Attempted")?;
        writeln!(report)?;
        writeln!(report, "| Rank | Password | Attempts |")?;
        writeln!(report, "|------|----------|----------|")?;
        for (i, (password, count)) in password_vec.iter().take(10).enumerate() {
            writeln!(report, "| {} | `{}` | {} |", i + 1, password, count)?;
        }
        writeln!(report)?;

        // Recent attempts
        writeln!(report, "## Recent Authentication Attempts")?;
        writeln!(report)?;
        writeln!(report, "| Timestamp | Username | Password |")?;
        writeln!(report, "|-----------|----------|----------|")?;
        for record in records.iter().take(20) {
            let password_display = record.password.as_deref().unwrap_or("*no password*");
            writeln!(report, "| {} | `{}` | `{}` |",
                record.timestamp.format("%Y-%m-%d %H:%M:%S"),
                record.username,
                password_display)?;
        }
        writeln!(report)?;

        // Detailed data section
        writeln!(report, "## Complete Authentication Data")?;
        writeln!(report)?;
        writeln!(report, "<details>")?;
        writeln!(report, "<summary>Show all authentication attempts with complete details</summary>")?;
        writeln!(report)?;
        writeln!(report, "| Timestamp | Username | Password | Country | City | ISP | Abuse Score | Tor | Reports |")?;
        writeln!(report, "|-----------|----------|----------|---------|------|-----|-------------|-----|---------|")?;
        for record in records.iter() {
            let password_display = record.password.as_deref().unwrap_or("*no password*");
            let country_display = record.country.as_deref().unwrap_or("-");
            let city_display = record.city.as_deref().unwrap_or("-");
            let isp_display = record.isp.as_deref().unwrap_or("-");
            let abuse_score_display = record.abuse_confidence_score.map_or("-".to_string(), |s| format!("{}%", s));
            let tor_display = record.is_tor.map_or("-".to_string(), |t| if t { "Yes".to_string() } else { "No".to_string() });
            let reports_display = record.total_reports.map_or("-".to_string(), |r| r.to_string());

            writeln!(report, "| {} | `{}` | `{}` | {} | {} | {} | {} | {} | {} |",
                record.timestamp.format("%Y-%m-%d %H:%M:%S"),
                record.username,
                password_display,
                country_display,
                city_display,
                isp_display,
                abuse_score_display,
                tor_display,
                reports_display)?;
        }
        writeln!(report)?;
        writeln!(report, "</details>")?;
        writeln!(report)?;

        writeln!(report, "---")?;
        writeln!(report, "*Report generated by SSH Honeypot Report Generator*")?;

        Ok(report)
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ReportFormat {
    Text,
    Html,
    Markdown,
}
