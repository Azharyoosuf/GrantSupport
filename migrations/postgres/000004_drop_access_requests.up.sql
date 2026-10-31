-- 000004_drop_access_requests.up.sql (PostgreSQL)

DROP INDEX IF EXISTS idx_gs_access_requests_inst_status;
DROP INDEX IF EXISTS idx_gs_access_requests_requester;
DROP INDEX IF EXISTS idx_gs_access_requests_expires;
DROP TABLE IF EXISTS gs_access_requests CASCADE;

