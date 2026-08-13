-- 000001_initial_grantsupport_schema.up.sql (SQLite 3)

CREATE TABLE IF NOT EXISTS gs_support_grants (
    id TEXT PRIMARY KEY,
    institution_id TEXT NOT NULL,
    granted_by_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    used_at DATETIME,
    scope TEXT NOT NULL DEFAULT 'FULL_ACCESS',
    whitelisted_ips TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_support_grants_inst_exp ON gs_support_grants (institution_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_gs_support_grants_token_hash ON gs_support_grants (token_hash);

CREATE TABLE IF NOT EXISTS gs_audit_events (
    id TEXT PRIMARY KEY,
    institution_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    hash_chain TEXT,
    signature TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_audit_events_inst_created ON gs_audit_events (institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gs_audit_events_actor ON gs_audit_events (actor_id);
CREATE INDEX IF NOT EXISTS idx_gs_audit_events_type ON gs_audit_events (event_type);

CREATE TABLE IF NOT EXISTS gs_locks (
    lock_key TEXT PRIMARY KEY,
    owner_token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    acquired_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_locks_expires_at ON gs_locks (expires_at);

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key TEXT PRIMARY KEY,
    expires_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_replays_expires_at ON gs_replays (expires_at);

CREATE TABLE IF NOT EXISTS gs_revocations (
    institution_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 1,
    revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, user_id)
);
