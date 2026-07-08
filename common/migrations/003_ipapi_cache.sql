-- IPAPI cache table with automatic expiration
CREATE TABLE ipapi_cache (
    ip INET PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    country VARCHAR(100),
    country_code VARCHAR(2),
    region VARCHAR(100),
    region_name VARCHAR(100),
    city VARCHAR(100),
    zip VARCHAR(20),
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION,
    timezone VARCHAR(100),
    isp VARCHAR(255),
    org VARCHAR(255),
    as_info VARCHAR(255),
    response_data JSONB NOT NULL
);

-- Index for performance
CREATE INDEX idx_ipapi_cache_timestamp ON ipapi_cache(timestamp);

-- Comment for documentation
COMMENT ON TABLE ipapi_cache IS 'Cached IPAPI IP geolocation data';
COMMENT ON COLUMN ipapi_cache.response_data IS 'Full IPAPI response as JSONB for rich queries';