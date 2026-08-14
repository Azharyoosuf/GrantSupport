-- 000002_add_used_by_id_to_support_grants.up.sql (MySQL 8.0+)
ALTER TABLE gs_support_grants ADD COLUMN used_by_id VARCHAR(36) NULL;
CREATE INDEX idx_gs_support_grants_used_by ON gs_support_grants (institution_id, used_by_id);
