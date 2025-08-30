use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use reqwest::{Method, StatusCode};
use reqwest::tls::Version;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use crate::db::{record_abuse_ip_check, get_abuse_ip_check};

const DEFAULT_CACHE_TTL_HOURS: u8 = 24;

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    #[allow(dead_code)]
    pub limit: Option<u32>,
    #[allow(dead_code)]
    pub remaining: Option<u32>,
    pub reset_timestamp: Option<u64>,
    pub retry_after_seconds: Option<u32>,
}

#[derive(Debug)]
pub enum AbuseIpError {
    RateLimitExceeded(RateLimitInfo),
    NetworkError(reqwest::Error),
    Other(String),
}

impl std::fmt::Display for AbuseIpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbuseIpError::RateLimitExceeded(info) => {
                if let Some(retry_after) = info.retry_after_seconds {
                    write!(f, "Daily API rate limit exceeded. Retry after {} seconds", retry_after)
                } else if let Some(reset_timestamp) = info.reset_timestamp {
                    let now = Utc::now().timestamp() as u64;
                    let wait_seconds = if reset_timestamp > now { reset_timestamp - now } else { 0 };
                    write!(f, "Daily API rate limit exceeded. Resets in {} seconds", wait_seconds)
                } else {
                    write!(f, "Daily API rate limit exceeded")
                }
            },
            AbuseIpError::NetworkError(e) => write!(f, "Network error: {}", e),
            AbuseIpError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AbuseIpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AbuseIpError::NetworkError(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for CheckResponseData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IP: {}", self.ip_address)?;
        
        if let Some(confidence) = self.abuse_confidence_score {
            write!(f, ", Confidence: {}%", confidence)?;
        }
        
        if let Some(country) = &self.country_code {
            write!(f, ", Country: {}", country)?;
        }
        
        if let Some(isp) = &self.isp {
            write!(f, ", ISP: {}", isp)?;
        }
        
        if let Some(usage_type) = &self.usage_type {
            write!(f, ", Usage: {}", usage_type)?;
        }
        
        write!(f, ", Reports: {}", self.total_reports)?;
        
        if self.is_tor {
            write!(f, ", Tor: true")?;
        }
        
        if let Some(allowlisted) = self.is_allowlisted {
            if allowlisted {
                write!(f, ", Allowlisted: true")?;
            }
        }
        
        if let Some(domain) = &self.domain {
            write!(f, ", Domain: {}", domain)?;
        }
        
        if let Some(hostnames) = &self.hostnames {
            if !hostnames.is_empty() {
                write!(f, ", Hostnames: [{}]", hostnames.join(", "))?;
            }
        }
        
        if let Some(last_reported) = &self.last_reported_at {
            write!(f, ", LastReported: {}", last_reported)?;
        }
        
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct CheckResponseData {
    #[serde(rename = "abuseConfidenceScore")]
    pub abuse_confidence_score: Option<u8>,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    pub domain: Option<String>,
    pub hostnames: Option<Vec<String>>,
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    #[serde(rename = "ipVersion")]
    pub ip_version: u8,
    #[serde(rename = "isPublic")]
    pub is_public: bool,
    #[serde(rename = "isTor")]
    pub is_tor: bool,
    #[serde(rename = "isWhitelisted")]
    pub is_allowlisted: Option<bool>,
    pub isp: Option<String>,
    #[serde(rename = "lastReportedAt")]
    pub last_reported_at: Option<String>,
    #[serde(rename = "numDistinctUsers")]
    pub num_distinct_users: u32,
    #[serde(rename = "totalReports")]
    pub total_reports: u32,
    #[serde(rename = "usageType")]
    pub usage_type: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct CheckResponse {
    pub data: CheckResponseData
}

#[derive(Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct ReportResponseData {
    #[serde(rename = "ipAddress")]
    ip_address: String,
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: String
}

#[derive(Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct ReportResponse {
    pub data: ReportResponseData
}

#[derive(Clone, Debug)]
pub struct CachedResult {
    pub response: CheckResponse,
    pub cached_at: DateTime<Utc>,
}

pub struct Client {
    client: reqwest::Client,
    api_key: String,
    pub memory_cache: Arc<RwLock<HashMap<String, CachedResult>>>,
    pool: PgPool,
    pub cache_ttl_hours: u8,
}

impl Client {
    pub fn new(api_key: String, pool: PgPool, cache_ttl_hours: Option<u8>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .min_tls_version(Version::TLS_1_2)
                .https_only(true)
                .deflate(true)
                .brotli(true)
                .use_rustls_tls()
                .tls_built_in_root_certs(true)
                .build()
                .unwrap(),
            api_key,
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            pool,
            cache_ttl_hours: cache_ttl_hours.unwrap_or(DEFAULT_CACHE_TTL_HOURS),
        }
    }

    pub async fn check_ip_with_cache(&self, ip_address: &str) -> Result<CheckResponse, AbuseIpError> {
        // First check memory cache
        let cache = self.memory_cache.read().await;
        if let Some(cached) = cache.get(ip_address) {
            let age = Utc::now() - cached.cached_at;
            if age < Duration::hours(self.cache_ttl_hours as i64) {
                log::debug!("AbuseIPDB memory cache hit for IP: {}", ip_address);
                return Ok(cached.response.clone());
            }
        }
        drop(cache); // Release read lock
        
        // Check database cache
        match get_abuse_ip_check(&self.pool, ip_address, self.cache_ttl_hours).await {
            Ok(Some((timestamp, response_data))) => {
                log::debug!("AbuseIPDB database cache hit for IP: {}", ip_address);
                let response = CheckResponse { data: response_data };
                
                // Update memory cache
                let mut cache = self.memory_cache.write().await;
                cache.insert(ip_address.to_string(), CachedResult {
                    response: response.clone(),
                    cached_at: timestamp,
                });
                
                return Ok(response);
            },
            Ok(None) => {
                // No cache entry or expired - continue to API call
            },
            Err(e) => {
                log::error!("Failed to query AbuseIPDB cache: {}", e);
                // Continue to API call on database error
            }
        }
        
        // Cache miss or expired, make API call
        log::debug!("AbuseIPDB cache miss for IP: {}, making API call", ip_address);
        let response = self.check_ip_api(ip_address).await?;
        
        // Update memory cache
        let mut cache = self.memory_cache.write().await;
        let now = Utc::now();
        cache.insert(ip_address.to_string(), CachedResult {
            response: response.clone(),
            cached_at: now,
        });
        drop(cache);
        
        // Store in database cache
        if let Err(e) = record_abuse_ip_check(
            &self.pool,
            ip_address.to_string(),
            now,
            response.data.abuse_confidence_score,
            response.data.country_code.clone(),
            response.data.is_tor,
            response.data.is_allowlisted,
            response.data.total_reports,
            serde_json::to_string(&response.data).unwrap_or_default(),
        ).await {
            log::error!("Failed to cache AbuseIPDB result in database: {}", e);
        }
        
        Ok(response)
    }

    async fn check_ip_api(&self, ip_address: &str) -> Result<CheckResponse, AbuseIpError> {
        let mut querystring = HashMap::new();
        querystring.insert("ipAddress", ip_address);
        querystring.insert("maxAgeInDays", "90");
        
        let res = self.client.request(Method::GET, "https://api.abuseipdb.com/api/v2/check")
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&querystring)
            .send()
            .await
            .map_err(AbuseIpError::NetworkError)?;

        // Check for rate limiting
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            let rate_limit_info = self.parse_rate_limit_headers(&res);
            return Err(AbuseIpError::RateLimitExceeded(rate_limit_info));
        }

        // Check for other HTTP errors
        if !res.status().is_success() {
            return Err(AbuseIpError::Other(format!("HTTP {}: {}", res.status(), res.status().canonical_reason().unwrap_or("Unknown error"))));
        }

        res.json().await.map_err(AbuseIpError::NetworkError)
    }

    fn parse_rate_limit_headers(&self, response: &reqwest::Response) -> RateLimitInfo {
        let headers = response.headers();
        
        RateLimitInfo {
            limit: headers.get("X-RateLimit-Limit")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse().ok()),
            remaining: headers.get("X-RateLimit-Remaining")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse().ok()),
            reset_timestamp: headers.get("X-RateLimit-Reset")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse().ok()),
            retry_after_seconds: headers.get("Retry-After")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse().ok()),
        }
    }

    #[allow(dead_code)]
    // 2023-10-18T11:25:11-04:00 is the format of the timestamp
    pub async fn report_ip(&self, ip_address: &str, categories: &Vec<u8>, evidence: &str, timestamp: &str) -> Result<ReportResponse, reqwest::Error> {
        // Really rust? You could just do categories.join(","), but rust says no
        let formatted_categories: String = categories.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");
        let mut querystring = HashMap::new();
        querystring.insert("ip", ip_address);
        querystring.insert("categories", &formatted_categories);
        querystring.insert("comment", evidence);
        querystring.insert("timestamp", timestamp);
        let res = self.client.request(Method::POST, "https://api.abuseipdb.com/api/v2/report")
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&querystring)
            .send()
            .await?;
        res.json().await
    }
}