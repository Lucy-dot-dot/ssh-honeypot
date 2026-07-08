-- Migration 006: Add IP intelligence data columns to auth table
-- Stores point-in-time snapshots of AbuseIPDB and IPAPI data with each auth attempt

ALTER TABLE auth ADD COLUMN abuseipdb_data JSONB;
ALTER TABLE auth ADD COLUMN ipapi_data JSONB;

COMMENT ON COLUMN auth.abuseipdb_data IS 'Point-in-time AbuseIPDB response data at time of auth attempt';
COMMENT ON COLUMN auth.ipapi_data IS 'Point-in-time IPAPI geolocation data at time of auth attempt';
