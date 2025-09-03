-- Enriched password authentication view with IP intelligence data
-- Merges password auth attempts with IPAPI geolocation and AbuseIPDB threat intelligence
-- AbuseIPDB data takes precedence for overlapping fields (country_code, ISP)
CREATE VIEW auth_password_enriched AS
SELECT
    -- Core authentication data
    a.id,
    a.timestamp,
    a.ip,
    a.username,
    a.password,

    -- Country information (AbuseIPDB takes precedence)
    COALESCE(abuse.country_code, ipapi.country_code) AS country_code,
    ipapi.country,
    ipapi.region,
    ipapi.region_name,
    ipapi.city,
    ipapi.zip,

    -- Geographic coordinates (from IPAPI)
    ipapi.lat,
    ipapi.lon,
    ipapi.timezone,

    -- ISP/Organization information (AbuseIPDB takes precedence for ISP)
    COALESCE(
            CASE WHEN abuse.response_data->>'isp' IS NOT NULL AND abuse.response_data->>'isp' != ''
                     THEN abuse.response_data->>'isp'
                 ELSE NULL
                END,
            ipapi.isp
    ) AS isp,
    ipapi.org,
    ipapi.as_info,

    -- AbuseIPDB threat intelligence (exclusive to AbuseIPDB)
    abuse.abuse_confidence_score,
    abuse.is_tor,
    abuse.is_whitelisted,
    abuse.total_reports,
    abuse.timestamp AS abuse_check_timestamp,

    -- IPAPI data timestamp
    ipapi.timestamp AS ipapi_check_timestamp,

    -- Full response data for advanced queries
    abuse.response_data AS abuse_response_data,
    ipapi.response_data AS ipapi_response_data

FROM auth a
         LEFT JOIN abuse_ip_cache abuse ON a.ip = abuse.ip
         LEFT JOIN ipapi_cache ipapi ON a.ip = ipapi.ip;

-- Comment for documentation
COMMENT ON VIEW auth_password_enriched IS 'Enriched authentication password attempts with IP geolocation and threat intelligence. AbuseIPDB data takes precedence for overlapping fields like country_code and ISP.';