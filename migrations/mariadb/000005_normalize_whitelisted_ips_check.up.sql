-- 000005_normalize_whitelisted_ips_check.up.sql (MariaDB 10.5+)
-- Normalize the inline JSON CHECK constraint on gs_support_grants.whitelisted_ips
-- so that Atlas / Ent Schema.Create recognizes the column as MariaDB JSON.

ALTER TABLE gs_support_grants
    MODIFY COLUMN whitelisted_ips LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL CHECK (json_valid(whitelisted_ips));

