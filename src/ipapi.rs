use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use reqwest::{Method, StatusCode};
use reqwest::tls::Version;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use crate::db::{record_ipapi_check, get_ipapi_check};

const DEFAULT_CACHE_TTL_HOURS: u8 = 24;

#[derive(Debug)]
pub enum IpApiError {
    RateLimitExceeded,
    NetworkError(reqwest::Error),
    Other(String),
}

impl std::fmt::Display for IpApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpApiError::RateLimitExceeded => write!(f, "IPAPI rate limit exceeded"),
            IpApiError::NetworkError(e) => write!(f, "Network error: {}", e),
            IpApiError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for IpApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IpApiError::NetworkError(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CachedResult {
    pub response: IpApiResponse,
    pub cached_at: DateTime<Utc>,
}

pub struct Client {
    client: reqwest::Client,
    pub memory_cache: Arc<RwLock<HashMap<String, CachedResult>>>,
    pool: PgPool,
    pub cache_ttl_hours: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialOrd, PartialEq)]
pub struct IpApiResponse {
    pub status: String,
    pub country: String,
    #[serde(rename = "countryCode")]
    pub country_code: String,
    pub region: String,
    #[serde(rename = "regionName")]
    pub region_name: String,
    pub city: String,
    pub zip: String,
    pub lat: f64,
    pub lon: f64,
    pub timezone: String,
    pub isp: String,
    pub org: String,
    #[serde(rename = "as")]
    pub r#as: String,
    pub query: String,
}

impl Client {
    pub fn new(pool: PgPool, cache_ttl_hours: Option<u8>) -> Self {
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
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            pool,
            cache_ttl_hours: cache_ttl_hours.unwrap_or(DEFAULT_CACHE_TTL_HOURS),
        }
    }

    pub async fn check_ip_with_cache(&self, ip_address: &str) -> Result<IpApiResponse, IpApiError> {
        // First check memory cache
        let cache = self.memory_cache.read().await;
        if let Some(cached) = cache.get(ip_address) {
            let age = Utc::now() - cached.cached_at;
            if age < Duration::hours(self.cache_ttl_hours as i64) {
                log::debug!("IPAPI memory cache hit for IP: {}", ip_address);
                return Ok(cached.response.clone());
            }
        }
        drop(cache); // Release read lock
        
        // Check database cache
        match get_ipapi_check(&self.pool, ip_address, self.cache_ttl_hours).await {
            Ok(Some((timestamp, response))) => {
                log::debug!("IPAPI database cache hit for IP: {}", ip_address);
                
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
                log::error!("Failed to query IPAPI cache: {}", e);
                // Continue to API call on database error
            }
        }
        
        // Cache miss or expired, make API call
        log::debug!("IPAPI cache miss for IP: {}, making API call", ip_address);
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
        if let Err(e) = record_ipapi_check(
            &self.pool,
            ip_address.to_string(),
            now,
            Some(response.country.clone()),
            Some(response.country_code.clone()),
            Some(response.region.clone()),
            Some(response.region_name.clone()),
            Some(response.city.clone()),
            Some(response.zip.clone()),
            Some(response.lat),
            Some(response.lon),
            Some(response.timezone.clone()),
            Some(response.isp.clone()),
            Some(response.org.clone()),
            Some(response.r#as.clone()),
            serde_json::to_string(&response).unwrap_or_default(),
        ).await {
            log::error!("Failed to cache IPAPI result in database: {}", e);
        }
        
        Ok(response)
    }

    async fn check_ip_api(&self, ip_address: &str) -> Result<IpApiResponse, IpApiError> {
        // Apparently ip-api.com doesn't support https for free requests. Wtf.
        // FIXME: Use a different API provider
        let url = format!("http://ip-api.com/json/{}", ip_address);
        let res = self.client.
            request(Method::GET, url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(IpApiError::NetworkError)?;

        // Check for rate limiting (ip-api.com returns 429 for rate limits)
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(IpApiError::RateLimitExceeded);
        }

        // Check for other HTTP errors
        if !res.status().is_success() {
            return Err(IpApiError::Other(format!("HTTP {}: {}", res.status(), res.status().canonical_reason().unwrap_or("Unknown error"))));
        }

        res.json().await.map_err(IpApiError::NetworkError)
    }
}