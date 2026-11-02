-- 000005_normalize_whitelisted_ips_check.down.sql (MariaDB 10.5+)
-- Restore the original 000001 column definition for gs_support_grants.whitelisted_ips.

ALTER TABLE gs_support_grants
    MODIFY COLUMN whitelisted_ips LONGTEXT NULL CHECK (whitelisted_ips IS NULL OR JSON_VALID(whitelisted_ips));

