-- 000004_drop_access_requests.up.sql (MySQL 8.0+)
-- Dropping the InnoDB table automatically drops its inline indexes
-- (idx_gs_access_requests_inst_status, idx_gs_access_requests_requester, idx_gs_access_requests_expires).

DROP TABLE IF EXISTS gs_access_requests;

