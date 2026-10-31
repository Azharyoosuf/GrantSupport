-- 000006_drop_replays.down.sql
-- Dialect: MySQL 8.0+
-- Restores the gs_replays table as defined in 000001_initial_grantsupport_schema.up.sql.

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key VARCHAR(255) PRIMARY KEY,
    expires_at DATETIME(6) NOT NULL,
    INDEX idx_gs_replays_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

