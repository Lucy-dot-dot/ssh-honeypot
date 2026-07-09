//! RDAP (Registration Data Access Protocol) client for looking up WHOIS-style
//! information about an IP address from the dashboard. Results are cached in
//! memory for the lifetime of the process so repeated clicks on the same IP
//! are instant.
//!
//! RDAP is the JSON successor to the classic WHOIS protocol. The bootstrap
//! endpoint `https://rdap.org/ip/{ip}` redirects (HTTP 302) to the authoritative
//! Regional Internet Registry, which returns structured data: network name,
//! country, CIDR, abuse contact, registration / last-changed events, etc. This
//! avoids the unstructured, registrar-varying text of port-43 WHOIS.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// How long a single RDAP request may take before we give up.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const RDAP_BOOTSTRAP: &str = "https://rdap.org/ip";

/// Parsed, display-ready WHOIS/RDAP information for an IP.
#[derive(Clone, Debug)]
pub struct WhoisInfo {
    pub network_name: Option<String>,
    pub country: Option<String>,
    pub handle: Option<String>,
    pub net_type: Option<String>,
    pub range: Option<String>,
    pub cidr: Option<String>,
    pub status: Option<String>,
    pub abuse_email: Option<String>,
    pub abuse_name: Option<String>,
    pub registration: Option<String>,
    pub last_changed: Option<String>,
    pub description: Option<String>,
    pub fetched_at: DateTime<Utc>,
}

/// Lightweight RDAP-over-HTTPS client with an in-memory cache. Cheaply clonable
/// (the HTTP client and cache both live behind cheap-to-clone handles) so it can
/// be moved into background tasks.
#[derive(Clone)]
pub struct WhoisClient {
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, WhoisInfo>>>,
}

impl WhoisClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!(
                "ssh-honeypot-dashboard/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .unwrap_or_default();
        Self {
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Look up RDAP info for `ip`. Returns a cached result immediately when one
    /// exists; otherwise fetches, parses, caches, and returns it.
    pub async fn lookup(&self, ip: &str) -> Result<WhoisInfo, String> {
        let key = ip.trim().to_lowercase();

        if let Some(info) = self.cache.read().await.get(&key) {
            return Ok(info.clone());
        }

        let url = format!("{RDAP_BOOTSTRAP}/{key}");
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/rdap+json, application/json")
            .send()
            .await
            .map_err(|e| format!("RDAP request failed: {e}"))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err("No RDAP record for this IP".to_string());
        }
        if !resp.status().is_success() {
            return Err(format!("RDAP server returned HTTP {}", resp.status()));
        }

        let value: Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse RDAP response: {e}"))?;

        let info = parse_rdap(&value);
        self.cache.write().await.insert(key, info.clone());
        Ok(info)
    }
}

impl Default for WhoisClient {
    fn default() -> Self {
        Self::new()
    }
}

// --- RDAP JSON parsing ---------------------------------------------------

fn parse_rdap(root: &Value) -> WhoisInfo {
    let (abuse_name, abuse_email) = find_abuse_contact(root);
    let (registration, last_changed) = parse_events(root);

    WhoisInfo {
        network_name: root.get("name").and_then(str_value),
        country: root.get("country").and_then(str_value),
        handle: root.get("handle").and_then(str_value),
        net_type: root.get("type").and_then(str_value),
        range: parse_range(root),
        cidr: parse_cidr(root),
        status: parse_status(root),
        abuse_email,
        abuse_name,
        registration,
        last_changed,
        description: parse_remarks(root),
        fetched_at: Utc::now(),
    }
}

fn str_value(v: &Value) -> Option<String> {
    v.as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Walk the (possibly nested) `entities` tree and extract the abuse contact's
/// name + email from its vCard. Abuse contacts are often nested under a
/// registrant entity, hence the recursive walk.
fn find_abuse_contact(root: &Value) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut email = None;
    walk_entities(root, &mut |entity: &Value| {
        if !(name.is_none() || email.is_none()) {
            return;
        }
        if has_role(entity, "abuse") {
            if let Some(vc) = entity.get("vcardArray") {
                if name.is_none() {
                    name = vcard_field(vc, "fn");
                }
                if email.is_none() {
                    email = vcard_field(vc, "email");
                }
            }
        }
    });
    (name, email)
}

fn walk_entities<F: FnMut(&Value)>(val: &Value, f: &mut F) {
    if let Some(arr) = val.get("entities").and_then(|v| v.as_array()) {
        for e in arr {
            f(e);
            walk_entities(e, f);
        }
    }
}

fn has_role(entity: &Value, role: &str) -> bool {
    entity
        .get("roles")
        .and_then(|v| v.as_array())
        .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some(role)))
}

/// Extract a single field (e.g. "email", "fn") from a jCard/vCard array. A
/// vCard entry has the shape `[name, params, type, value]`.
fn vcard_field(vcard: &Value, field: &str) -> Option<String> {
    let entries = vcard.as_array()?.get(1)?.as_array()?;
    for entry in entries {
        let parts = entry.as_array()?;
        if parts.first().and_then(|v| v.as_str()) == Some(field) {
            return json_value_to_string(parts.get(3)?);
        }
    }
    None
}

/// Coerce a JSON value into a display string, joining array values with "; ".
fn json_value_to_string(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.trim().to_string()).filter(|s| !s.is_empty());
    }
    if let Some(arr) = v.as_array() {
        let joined = arr
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        if !joined.is_empty() {
            return Some(joined);
        }
    }
    None
}

/// Turn the `cidr0_cidrs` array into a "prefix/length" string when present.
fn parse_cidr(root: &Value) -> Option<String> {
    let cidrs = root.get("cidr0_cidrs")?.as_array()?;
    let mut parts = Vec::new();
    for c in cidrs {
        let (prefix_key, prefix) = if let Some(p) = c.get("v4prefix") {
            ("v4prefix", p)
        } else if let Some(p) = c.get("v6prefix") {
            ("v6prefix", p)
        } else {
            continue;
        };
        let _ = prefix_key;
        if let (Some(addr), Some(len)) = (
            prefix.as_str().map(str::trim).filter(|s| !s.is_empty()),
            c.get("length").and_then(|v| v.as_u64()),
        ) {
            parts.push(format!("{addr}/{len}"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Build a "startAddress \u{2013} endAddress" string.
fn parse_range(root: &Value) -> Option<String> {
    let start = root.get("startAddress").and_then(str_value)?;
    let end = root.get("endAddress").and_then(str_value)?;
    Some(format!("{start} \u{2013} {end}"))
}

/// Find the registration + last-changed dates from the top-level `events`.
fn parse_events(root: &Value) -> (Option<String>, Option<String>) {
    let mut registration = None;
    let mut last_changed = None;
    if let Some(events) = root.get("events").and_then(|v| v.as_array()) {
        for ev in events {
            let action = ev.get("eventAction").and_then(|v| v.as_str());
            let date = ev.get("eventDate").and_then(str_value);
            match action {
                Some("registration") if registration.is_none() => registration = date,
                Some("last changed") if last_changed.is_none() => last_changed = date,
                _ => {}
            }
        }
    }
    (registration, last_changed)
}

/// Concatenate the `description` lines from `remarks` into a single block.
fn parse_remarks(root: &Value) -> Option<String> {
    let remarks = root.get("remarks").and_then(|v| v.as_array())?;
    let mut lines = Vec::new();
    for remark in remarks {
        if let Some(desc) = remark.get("description").and_then(|v| v.as_array()) {
            for line in desc {
                if let Some(s) = line.as_str() {
                    lines.push(s.to_string());
                }
            }
        }
    }
    let joined = lines.join("\n");
    if joined.trim().is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// Join the top-level `status` array into a comma-separated string.
fn parse_status(root: &Value) -> Option<String> {
    let joined = root
        .get("status")
        .and_then(|v| v.as_array())?
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rdap() -> &'static str {
        r#"{
            "objectClassName": "ip network",
            "handle": "203.0.113.0 - 203.0.113.255",
            "startAddress": "203.0.113.0",
            "endAddress": "203.0.113.255",
            "ipVersion": "v4",
            "name": "EXAMPLENET",
            "type": "ASSIGNED PORTABLE",
            "country": "AU",
            "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
            "status": ["active"],
            "events": [
                {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2020-02-02T00:00:00Z"}
            ],
            "remarks": [{"description": ["Example remarks", "second line"]}],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard",
                        [["version", {}, "text", "4.0"],
                         ["fn", {}, "text", "Example Org"],
                         ["org", {}, "text", "Example Org Pty Ltd"]]]
                },
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard",
                        [["version", {}, "text", "4.0"],
                         ["fn", {}, "text", "Abuse Desk"],
                         ["email", {}, "text", "abuse@example.net"]]]
                }
            ]
        }"#
    }

    #[test]
    fn parses_core_fields() {
        let value: Value = serde_json::from_str(sample_rdap()).unwrap();
        let info = parse_rdap(&value);
        assert_eq!(info.network_name.as_deref(), Some("EXAMPLENET"));
        assert_eq!(info.country.as_deref(), Some("AU"));
        assert_eq!(info.net_type.as_deref(), Some("ASSIGNED PORTABLE"));
        assert_eq!(info.cidr.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(
            info.range.as_deref(),
            Some("203.0.113.0 \u{2013} 203.0.113.255")
        );
        assert_eq!(info.abuse_email.as_deref(), Some("abuse@example.net"));
        assert_eq!(info.abuse_name.as_deref(), Some("Abuse Desk"));
        assert_eq!(
            info.registration.as_deref(),
            Some("2000-01-01T00:00:00Z")
        );
        assert_eq!(
            info.last_changed.as_deref(),
            Some("2020-02-02T00:00:00Z")
        );
        assert_eq!(info.status.as_deref(), Some("active"));
        assert!(info.description.as_deref().unwrap().contains("second line"));
    }

    #[test]
    fn handles_minimal_object() {
        let value: Value = serde_json::from_str(r#"{"objectClassName":"ip network"}"#).unwrap();
        let info = parse_rdap(&value);
        assert!(info.network_name.is_none());
        assert!(info.abuse_email.is_none());
    }

    #[test]
    fn handles_empty_arrays() {
        let value: Value = serde_json::from_str(
            r#"{"entities":[],"events":[],"status":[],"remarks":[]}"#,
        )
        .unwrap();
        let info = parse_rdap(&value);
        assert!(info.cidr.is_none());
        assert!(info.range.is_none());
        assert!(info.status.is_none());
        assert!(info.description.is_none());
    }
}
