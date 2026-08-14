-- 000002_add_used_by_id_to_support_grants.down.sql (MariaDB)
DROP INDEX IF EXISTS idx_gs_support_grants_used_by ON gs_support_grants;
ALTER TABLE gs_support_grants DROP COLUMN IF EXISTS used_by_id;
