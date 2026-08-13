-- 000001_initial_grantsupport_schema.up.sql (MariaDB 10.6+)

CREATE TABLE IF NOT EXISTS gs_support_grants (
    id VARCHAR(36) PRIMARY KEY,
    institution_id VARCHAR(36) NOT NULL,
    granted_by_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME(6) NOT NULL,
    is_used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME(6) NULL,
    scope VARCHAR(64) NOT NULL DEFAULT 'FULL_ACCESS',
    whitelisted_ips LONGTEXT NULL CHECK (whitelisted_ips IS NULL OR JSON_VALID(whitelisted_ips)),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_gs_support_grants_inst_exp (institution_id, expires_at),
    INDEX idx_gs_support_grants_token_hash (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_audit_events (
    id VARCHAR(36) PRIMARY KEY,
    institution_id VARCHAR(36) NOT NULL,
    actor_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT NULL,
    hash_chain VARCHAR(64) NULL,
    signature TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_gs_audit_events_inst_created (institution_id, created_at),
    INDEX idx_gs_audit_events_actor (actor_id),
    INDEX idx_gs_audit_events_type (event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_locks (
    lock_key VARCHAR(255) PRIMARY KEY,
    owner_token VARCHAR(64) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    acquired_at DATETIME(6) NOT NULL,
    INDEX idx_gs_locks_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key VARCHAR(255) PRIMARY KEY,
    expires_at DATETIME(6) NOT NULL,
    INDEX idx_gs_replays_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_revocations (
    institution_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    token_version INT NOT NULL DEFAULT 1,
    revoked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (institution_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
