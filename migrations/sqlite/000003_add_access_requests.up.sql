-- 000002_add_access_requests.up.sql (SQLite 3)

CREATE TABLE IF NOT EXISTS gs_access_requests (
    id TEXT PRIMARY KEY,
    institution_id TEXT NOT NULL,
    requester_id TEXT NOT NULL,
    target_service TEXT,
    reason TEXT NOT NULL,
    requested_duration_minutes INTEGER NOT NULL,
    approved_duration_minutes INTEGER,
    requested_scope TEXT NOT NULL DEFAULT 'FULL_ACCESS',
    approved_scope TEXT,
    requested_ips TEXT,
    approved_ips TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    expires_at DATETIME NOT NULL,
    approved_by_id TEXT,
    approved_at DATETIME,
    rejected_by_id TEXT,
    rejection_reason TEXT,
    rejected_at DATETIME,
    cancelled_at DATETIME,
    support_grant_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_access_requests_inst_status ON gs_access_requests (institution_id, status);
CREATE INDEX IF NOT EXISTS idx_gs_access_requests_requester ON gs_access_requests (institution_id, requester_id);
CREATE INDEX IF NOT EXISTS idx_gs_access_requests_expires ON gs_access_requests (expires_at);
