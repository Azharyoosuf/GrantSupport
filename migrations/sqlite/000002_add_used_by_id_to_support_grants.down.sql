-- 000002_add_used_by_id_to_support_grants.down.sql (SQLite)
DROP INDEX IF EXISTS idx_gs_support_grants_used_by;
ALTER TABLE gs_support_grants DROP COLUMN used_by_id;
