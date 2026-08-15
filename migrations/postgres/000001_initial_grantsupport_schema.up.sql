-- 000001_initial_grantsupport_schema.up.sql (PostgreSQL)

CREATE TABLE IF NOT EXISTS gs_support_grants (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    granted_by_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    scope VARCHAR(64) NOT NULL DEFAULT 'FULL_ACCESS',
    whitelisted_ips JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_support_grants_inst_exp ON gs_support_grants (institution_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_gs_support_grants_token_hash ON gs_support_grants (token_hash);

CREATE TABLE IF NOT EXISTS gs_audit_events (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT,
    hash_chain VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_audit_events_inst_created ON gs_audit_events (institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gs_audit_events_actor ON gs_audit_events (actor_id);
CREATE INDEX IF NOT EXISTS idx_gs_audit_events_type ON gs_audit_events (event_type);

CREATE TABLE IF NOT EXISTS gs_locks (
    lock_key VARCHAR(255) PRIMARY KEY,
    owner_token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_locks_expires_at ON gs_locks (expires_at);

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_replays_expires_at ON gs_replays (expires_at);

CREATE TABLE IF NOT EXISTS gs_revocations (
    institution_id UUID NOT NULL,
    user_id UUID NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 1,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, user_id)
);
