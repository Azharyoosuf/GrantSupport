-- 000002_add_access_requests.up.sql (PostgreSQL)

CREATE TABLE IF NOT EXISTS gs_access_requests (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    requester_id UUID NOT NULL,
    target_service VARCHAR(128),
    reason TEXT NOT NULL,
    requested_duration_minutes INTEGER NOT NULL,
    approved_duration_minutes INTEGER,
    requested_scope VARCHAR(64) NOT NULL DEFAULT 'FULL_ACCESS',
    approved_scope VARCHAR(64),
    requested_ips JSONB,
    approved_ips JSONB,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    expires_at TIMESTAMPTZ NOT NULL,
    approved_by_id UUID,
    approved_at TIMESTAMPTZ,
    rejected_by_id UUID,
    rejection_reason TEXT,
    rejected_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    support_grant_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_access_requests_inst_status ON gs_access_requests (institution_id, status);
CREATE INDEX IF NOT EXISTS idx_gs_access_requests_requester ON gs_access_requests (institution_id, requester_id);
CREATE INDEX IF NOT EXISTS idx_gs_access_requests_expires ON gs_access_requests (expires_at);
