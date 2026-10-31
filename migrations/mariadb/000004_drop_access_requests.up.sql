-- 000004_drop_access_requests.up.sql (MariaDB 10.5+)
-- Dropping the InnoDB table automatically drops its inline indexes
-- (idx_gs_access_requests_inst_status, idx_gs_access_requests_requester, idx_gs_access_requests_expires).

DROP TABLE IF EXISTS gs_access_requests;

