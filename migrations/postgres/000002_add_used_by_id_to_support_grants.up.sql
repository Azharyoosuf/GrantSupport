-- 000002_add_used_by_id_to_support_grants.up.sql (PostgreSQL)
ALTER TABLE gs_support_grants ADD COLUMN IF NOT EXISTS used_by_id UUID;
CREATE INDEX IF NOT EXISTS idx_gs_support_grants_used_by ON gs_support_grants (institution_id, used_by_id) WHERE is_used = TRUE;
