-- Change ip_address from INET to TEXT.
-- We store IPs as plain strings in JPA and never use inet operators or range queries.
ALTER TABLE audit_logs ALTER COLUMN ip_address TYPE TEXT USING ip_address::TEXT;
