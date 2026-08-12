# Phase 2 Implementation Plan: Multi-Database Support & SQL Migrations

## 📌 Problem & Context
1. **Empty `migrations/` Directory**: Missing SQL scripts for `SupportGrant`, `AuditEvent`, and immutability triggers.
2. **Hardcoded PostgreSQL Driver**: `main.go` hardcodes `ent.Open("postgres", ...)`, blocking MySQL/SQLite clients.
3. **No per-dialect `CREATE TABLE` scripts** for MySQL or SQLite (finding #13).

> **CGO decision (F-2-A)**: `github.com/mattn/go-sqlite3` requires CGO. Phase 3 builds with `CGO_ENABLED=0`. To resolve this conflict without splitting the Docker build, we replace the SQLite driver with **`modernc.org/sqlite`** (pure Go, zero CGO requirement). Phase 3's Dockerfile needs no changes for SQLite support.

> **Migration file directory structure (F-3-A fix)**: Migration files are organized into dialect-specific subdirectories to prevent PostgreSQL from ingesting MySQL scripts:
> - `migrations/postgres/` — PostgreSQL-only scripts
> - `migrations/mysql/` — MySQL-only scripts
> - `migrations/sqlite/` — SQLite-only scripts (trigger documentation only — see finding #29)
> Phase 3's docker-compose.yml mounts only `migrations/postgres/` into `docker-entrypoint-initdb.d`.

> **`DATABASE_DIALECT` allowlist (F-2-C)**: `LoadConfig()` now validates the dialect against a strict allowlist of `postgres`, `mysql`, `sqlite3` and returns a clear error on unknown values.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `migrations/postgres/` — PostgreSQL Migration Scripts

> **SEQUENCING CONSTRAINT (I-4 fix)**: The `hash_chain` column is created with `NOT NULL DEFAULT ''` in Phase 2's `000001` migration. The `CHECK (length(hash_chain) > 0)` constraint is intentionally **NOT** added in Phase 2. It will be added in `000003_add_hash_chain_check.sql`, which is applied as part of **Phase 5 deployment** — after `LogSecurityEvent` is updated to always write a real non-empty hash_chain value. Applying the CHECK constraint before Phase 5's code update would cause every `LogSecurityEvent` INSERT (from Phase 2/3/4 code) to violate the constraint and fail with a DB error. This sequencing dependency is stated explicitly in phase_5_plan.md.

#### [NEW] [000001_create_grantsupport_tables.sql](file:///d:/Hostel_management/GrantSupport/migrations/postgres/000001_create_grantsupport_tables.sql)

```sql
-- Migration 000001 (PostgreSQL): Create SupportGrant & AuditEvent tables.

CREATE TABLE IF NOT EXISTS "SupportGrant" (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    granted_by_id UUID NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN DEFAULT FALSE NOT NULL,
    used_at TIMESTAMPTZ,
    scope VARCHAR(64) DEFAULT 'FULL_ACCESS' NOT NULL,
    reason TEXT,
    whitelisted_ips JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS "AuditEvent" (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT,
    -- hash_chain: NOT NULL ensures no NULL chain values (finding #3 / #37).
    -- DEFAULT '' allows Phase 2/3/4 code to INSERT without setting this column;
    -- the stricter CHECK (length > 0) is added by 000003_add_hash_chain_check.sql
    -- which is applied during Phase 5 deployment ONLY, after LogSecurityEvent
    -- is updated to always write a real non-empty hash value.
    hash_chain VARCHAR(255) NOT NULL DEFAULT '',
    -- signature added for Ed25519 non-repudiation (Phase 5).
    signature VARCHAR(512),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auditevent_inst_created ON "AuditEvent"(institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_auditevent_actor ON "AuditEvent"(actor_id);
CREATE INDEX IF NOT EXISTS idx_auditevent_event_type ON "AuditEvent"(event_type);
```

#### [NEW] [000002_add_immutability_triggers.sql](file:///d:/Hostel_management/GrantSupport/migrations/postgres/000002_add_immutability_triggers.sql)

```sql
-- Migration 000002 (PostgreSQL): Append-only immutability triggers for AuditEvent.

CREATE OR REPLACE FUNCTION prevent_auditevent_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABLE_AUDIT_LOG: Modification or deletion of security audit records is strictly prohibited.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_auditevent_update ON "AuditEvent";
CREATE TRIGGER trg_prevent_auditevent_update
    BEFORE UPDATE ON "AuditEvent"
    FOR EACH ROW EXECUTE FUNCTION prevent_auditevent_mutation();

DROP TRIGGER IF EXISTS trg_prevent_auditevent_delete ON "AuditEvent";
CREATE TRIGGER trg_prevent_auditevent_delete
    BEFORE DELETE ON "AuditEvent"
    FOR EACH ROW EXECUTE FUNCTION prevent_auditevent_mutation();
```

---

### Component 2: `migrations/mysql/` — MySQL Migration Scripts

> **SEQUENCING CONSTRAINT (I-4 fix)**: Same as PostgreSQL. `hash_chain` is `NOT NULL DEFAULT ''` only in Phase 2. The `CHECK (LENGTH(hash_chain) > 0)` constraint is added in `000003_add_hash_chain_check.sql` applied during Phase 5 deployment.

#### [NEW] [000001_create_grantsupport_tables.sql](file:///d:/Hostel_management/GrantSupport/migrations/mysql/000001_create_grantsupport_tables.sql)

> MySQL does not have a native UUID type. Use `CHAR(36)` as the standard workaround.
> MySQL does not have a native JSONB type. Use `TEXT` for `whitelisted_ips`.

```sql
-- Migration 000001 (MySQL 8.0+): Create SupportGrant & AuditEvent tables.

CREATE TABLE IF NOT EXISTS SupportGrant (
    id CHAR(36) NOT NULL PRIMARY KEY,
    institution_id CHAR(36) NOT NULL,
    granted_by_id CHAR(36) NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    is_used TINYINT(1) DEFAULT 0 NOT NULL,
    used_at DATETIME,
    scope VARCHAR(64) DEFAULT 'FULL_ACCESS' NOT NULL,
    reason TEXT,
    whitelisted_ips TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS AuditEvent (
    id CHAR(36) NOT NULL PRIMARY KEY,
    institution_id CHAR(36) NOT NULL,
    actor_id CHAR(36) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT,
    -- hash_chain: NOT NULL only in Phase 2. CHECK (LENGTH > 0) added in Phase 5 migration 000003.
    hash_chain VARCHAR(255) NOT NULL DEFAULT '',
    signature VARCHAR(512),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX idx_auditevent_inst_created ON AuditEvent(institution_id, created_at);
CREATE INDEX idx_auditevent_actor ON AuditEvent(actor_id);
CREATE INDEX idx_auditevent_event_type ON AuditEvent(event_type);
```

#### [NEW] [000002_add_immutability_triggers.sql](file:///d:/Hostel_management/GrantSupport/migrations/mysql/000002_add_immutability_triggers.sql)

> **Fix (F-2-B)**: `DELIMITER` is a MySQL CLI-only command, not a SQL statement. Standard Go DB drivers cannot execute it. The triggers below use single-statement `CREATE TRIGGER` syntax that any MySQL 8.0 driver can execute directly.

```sql
-- Migration 000002 (MySQL 8.0+): Append-only immutability triggers.
-- Run each statement separately via your migration tool (no DELIMITER needed).

CREATE TRIGGER trg_prevent_auditevent_update
BEFORE UPDATE ON AuditEvent
FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'IMMUTABLE_AUDIT_LOG: AuditEvent updates are forbidden.';

CREATE TRIGGER trg_prevent_auditevent_delete
BEFORE DELETE ON AuditEvent
FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'IMMUTABLE_AUDIT_LOG: AuditEvent deletions are forbidden.';
```

---

### Component 3: `migrations/sqlite/` — SQLite Migration Scripts

> **SEQUENCING CONSTRAINT (I-4 fix)**: Same as PostgreSQL/MySQL. `hash_chain` is `NOT NULL DEFAULT ''` only in Phase 2. The `CHECK (length(hash_chain) > 0)` constraint is added in `000003_add_hash_chain_check.sql` applied during Phase 5 deployment.

#### [NEW] [000001_create_grantsupport_tables.sql](file:///d:/Hostel_management/GrantSupport/migrations/sqlite/000001_create_grantsupport_tables.sql)

> SQLite does not have native UUID or JSONB types. Use `TEXT` for both.

```sql
-- Migration 000001 (SQLite 3): Create SupportGrant & AuditEvent tables.

CREATE TABLE IF NOT EXISTS SupportGrant (
    id TEXT NOT NULL PRIMARY KEY,
    institution_id TEXT NOT NULL,
    granted_by_id TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    is_used INTEGER DEFAULT 0 NOT NULL,
    used_at TEXT,
    scope TEXT DEFAULT 'FULL_ACCESS' NOT NULL,
    reason TEXT,
    whitelisted_ips TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS AuditEvent (
    id TEXT NOT NULL PRIMARY KEY,
    institution_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    -- hash_chain: NOT NULL only in Phase 2. CHECK (length > 0) added in Phase 5 migration 000003.
    hash_chain TEXT NOT NULL DEFAULT '',
    signature TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auditevent_inst_created ON AuditEvent(institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_auditevent_actor ON AuditEvent(actor_id);
```

#### [NEW] [000002_immutability_limitation.md](file:///d:/Hostel_management/GrantSupport/migrations/sqlite/000002_immutability_limitation.md)

> **Known limitation (finding #29)**: SQLite 3 supports `BEFORE UPDATE/DELETE` triggers and `RAISE(ABORT, ...)`, which can block mutations. However, SQLite databases are single-process file-based stores. Any user with filesystem read/write access to the `.db` file can modify it directly bypassing triggers entirely. SQLite deployments therefore lack **database-level** tamper protection. This is a **documented accepted limitation** for SQLite-only deployments. For deployments requiring audit tamper-evidence, use PostgreSQL or MySQL.

---

### Component 4: `pkg/config/config.go` — Dialect Allowlist

#### [MODIFY] [config.go](file:///d:/Hostel_management/GrantSupport/pkg/config/config.go)

**BEFORE (struct definition):**
```go
type Config struct {
	DatabaseURL        string
	ValkeyCacheURL     string
	...
}
```

**AFTER:**
```go
type Config struct {
	// DatabaseDialect selects the SQL driver. Valid values: "postgres", "mysql", "sqlite3".
	DatabaseDialect     string
	DatabaseURL         string
	ValkeyCacheURL      string
	...
}
```

**BEFORE (LoadConfig, dialect section — does not exist yet):**
*(no dialect loading code)*

**AFTER (add inside LoadConfig, after reading dbURL):**
```go
	// Validate DATABASE_DIALECT against a strict allowlist (F-2-C).
	dbDialect := os.Getenv("DATABASE_DIALECT")
	switch dbDialect {
	case "postgres", "mysql", "sqlite3":
		// valid
	case "":
		dbDialect = "postgres" // default
	default:
		return nil, fmt.Errorf(
			"INVALID_DATABASE_DIALECT: %q is not a valid dialect; valid values are: postgres, mysql, sqlite3",
			dbDialect,
		)
	}
```

### Component 5: `cmd/server/main.go` — Multi-Dialect Driver Imports & Open

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go)

**BEFORE (import block, line 15):**
```go
	_ "github.com/jackc/pgx/v5/stdlib"
```

**AFTER:**
```go
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/go-sql-driver/mysql"
	// Pure-Go SQLite driver — no CGO required (modernc.org/sqlite replaces mattn/go-sqlite3 to avoid CGO conflict with Phase 3's CGO_ENABLED=0 Dockerfile).
	_ "modernc.org/sqlite"
```

**BEFORE (line 49):**
```go
	dbClient, err := ent.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to PostgreSQL database", slog.String("error", err.Error()))
		os.Exit(1)
	}
```

**AFTER:**
```go
	dbClient, err := ent.Open(cfg.DatabaseDialect, cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to database",
			slog.String("dialect", cfg.DatabaseDialect),
			slog.String("error", err.Error()))
		os.Exit(1)
	}
```

---

### Component 6: `go.mod` — New Driver Dependencies

Add these to `go.mod` (`go get` commands to run before building):
```bash
go get github.com/go-sql-driver/mysql@latest
go get modernc.org/sqlite@latest
```

---

## 🧪 Verification Plan

### Migration Verification (PostgreSQL)
```bash
psql -h localhost -p 5434 -U postgres -d grantsupport_db -f migrations/postgres/000001_create_grantsupport_tables.sql
psql -h localhost -p 5434 -U postgres -d grantsupport_db -f migrations/postgres/000002_add_immutability_triggers.sql
# Verify immutability trigger:
psql -h localhost -p 5434 -U postgres -d grantsupport_db -c 'DELETE FROM "AuditEvent";'
# Expect: ERROR: IMMUTABLE_AUDIT_LOG...
# Verify hash_chain CHECK constraint:
psql -h localhost -p 5434 -U postgres -d grantsupport_db -c \
  "INSERT INTO \"AuditEvent\" (id, institution_id, actor_id, event_type, hash_chain) VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'TEST', '');"
# Expect: ERROR: new row for relation "AuditEvent" violates check constraint
```

### Build Check
```bash
go build ./...
```
Expect: zero errors (modernc.org/sqlite is pure Go, no CGO conflict).

### Dialect Validation
Set `DATABASE_DIALECT=postgresql` and start server. Expect: startup error `INVALID_DATABASE_DIALECT: "postgresql" is not a valid dialect...`
