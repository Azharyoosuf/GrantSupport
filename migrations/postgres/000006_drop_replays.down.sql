-- 000006_drop_replays.down.sql
-- Dialect: PostgreSQL
-- Restores the gs_replays table as defined in 000001_initial_grantsupport_schema.up.sql.

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_replays_expires_at ON gs_replays (expires_at);

