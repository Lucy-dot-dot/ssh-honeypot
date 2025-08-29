use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, oneshot};
use chrono::{DateTime, Utc, Duration};
use reqwest::{Method, StatusCode};
use reqwest::tls::Version;
use serde::{Deserialize, Serialize};
use crate::db::DbMessage;

const DEFAULT_CACHE_TTL_DAYS: u8 = 7;

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub limit: Option<u32>,
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
    pub is_whitelisted: Option<bool>,
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
    db_tx: mpsc::Sender<DbMessage>,
    pub cache_ttl_days: u8,
}

impl Client {
    pub fn new(api_key: String, db_tx: mpsc::Sender<DbMessage>, cache_ttl_days: Option<u8>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .min_tls_version(Version::TLS_1_2)
                .https_only(true)
                .deflate(true)
                .brotli(true)
                .build()
                .unwrap(),
            api_key,
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            db_tx,
            cache_ttl_days: cache_ttl_days.unwrap_or(DEFAULT_CACHE_TTL_DAYS),
        }
    }

    pub async fn check_ip_with_cache(&self, ip_address: &str) -> Result<CheckResponse, AbuseIpError> {
        // First check memory cache
        let cache = self.memory_cache.read().await;
        if let Some(cached) = cache.get(ip_address) {
            let age = Utc::now() - cached.cached_at;
            if age < Duration::days(self.cache_ttl_days as i64) {
                log::debug!("AbuseIPDB memory cache hit for IP: {}", ip_address);
                return Ok(cached.response.clone());
            }
        }
        drop(cache); // Release read lock
        
        // Check database cache
        let (response_tx, response_rx) = oneshot::channel();
        if let Err(e) = self.db_tx.send(DbMessage::GetAbuseIpCheck {
            ip: ip_address.to_string(),
            cache_ttl_days: self.cache_ttl_days,
            response_tx,
        }).await {
            log::error!("Failed to send DB query for AbuseIPDB cache: {}", e);
        } else if let Ok(Some((timestamp, response_data))) = response_rx.await {
            log::debug!("AbuseIPDB database cache hit for IP: {}", ip_address);
            let response = CheckResponse { data: response_data };
            
            // Update memory cache
            let mut cache = self.memory_cache.write().await;
            cache.insert(ip_address.to_string(), CachedResult {
                response: response.clone(),
                cached_at: timestamp,
            });
            
            return Ok(response);
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
        if let Err(e) = self.db_tx.send(DbMessage::RecordAbuseIpCheck {
            ip: ip_address.to_string(),
            timestamp: now,
            abuse_confidence_score: response.data.abuse_confidence_score,
            country_code: response.data.country_code.clone(),
            is_tor: response.data.is_tor,
            is_whitelisted: response.data.is_whitelisted,
            total_reports: response.data.total_reports,
            response_data: serde_json::to_string(&response.data).unwrap_or_default(),
        }).await {
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