-- 000002_add_access_requests.up.sql (MariaDB 10.5+)

CREATE TABLE IF NOT EXISTS gs_access_requests (
    id VARCHAR(36) PRIMARY KEY,
    institution_id VARCHAR(36) NOT NULL,
    requester_id VARCHAR(36) NOT NULL,
    target_service VARCHAR(128) NULL,
    reason TEXT NOT NULL,
    requested_duration_minutes INT NOT NULL,
    approved_duration_minutes INT NULL,
    requested_scope VARCHAR(64) NOT NULL DEFAULT 'FULL_ACCESS',
    approved_scope VARCHAR(64) NULL,
    requested_ips LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL CHECK (json_valid(requested_ips)),
    approved_ips LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL CHECK (json_valid(approved_ips)),
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    expires_at DATETIME(6) NOT NULL,
    approved_by_id VARCHAR(36) NULL,
    approved_at DATETIME(6) NULL,
    rejected_by_id VARCHAR(36) NULL,
    rejection_reason TEXT NULL,
    rejected_at DATETIME(6) NULL,
    cancelled_at DATETIME(6) NULL,
    support_grant_id VARCHAR(36) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_gs_access_requests_inst_status (institution_id, status),
    INDEX idx_gs_access_requests_requester (institution_id, requester_id),
    INDEX idx_gs_access_requests_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
