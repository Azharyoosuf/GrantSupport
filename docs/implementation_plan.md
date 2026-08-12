# GrantSupport — Master Remediation & Enterprise Feature Roadmap

This document serves as the authoritative, phased technical implementation plan to resolve all code-documentation gaps, multi-database support requirements, missing Docker infrastructure, and enterprise security features for **GrantSupport**.

> **Canonical authoritative source**: Each phase listed here has a corresponding deep-detail plan document (`docs/phase_N_plan.md`). When this document and a phase plan conflict, **the phase plan governs**. This document is the executive summary and cross-reference index only.

---

## Executive Summary & Gap Matrix

| Remediation Phase | Category | Priority | Key Technical Deliverables |
| :--- | :--- | :---: | :--- |
| **Phase 1** | Code-Doc Parity | 🚨 **CRITICAL** | Implement `pkg/license` Ed25519 engine with startup caching; fix `SupportLogin` agent identity DTO; enforce strict Valkey fail-closed startup; add JWT key production guard; add `.env.example`. |
| **Phase 2** | DB & Migrations | 🚨 **CRITICAL** | Create `migrations/{postgres,mysql,sqlite}/` SQL files; pure-Go SQLite driver; dialect allowlist validation; MySQL triggers without DELIMITER; MySQL+SQLite CREATE TABLE scripts. |
| **Phase 3** | Containerization | 🚨 **CRITICAL** | Multi-stage `Dockerfile`; `docker-compose.yml` mounting only `migrations/postgres/` into postgres container; `MASTER_ENCRYPTION_KEY` via env var substitution (no hardcoded values); migration upgrade procedure documented. |
| **Phase 4** | Security Hardening | 🛡️ **HIGH** | Atomic Lua-based rate limiter; per-institution revocation with millisecond timestamps and fail-closed Valkey check; rate limiter wired in `main.go`; two revocation modes explicitly named. |
| **Phase 5** | Audit & Non-Repudiation | 🛡️ **HIGH** | Ent schema `signature` field added first; Ed25519 audit signing; PII redaction with fixed space-separated card regex; chain verification function; ALL call sites of changed `LogSecurityEvent` updated. |
| **Phase 6** | Scope & Webhooks | 💡 **MEDIUM** | `InstitutionWebhook` entity; HMAC-signed payloads; shutdown-aware dispatcher; `reason` field through full stack; scope deferred enforcement documented; **`pkg/encryption` AES-256-GCM package introduced** (I-8 fix); webhook registration controller + route added; `RegisterWebhook` method on controller. |
| **Phase 7** | Developer SDK & Client UI | 💡 **MEDIUM** | SDK `MountRoutes` with auth middleware, rate limiter, **and webhook registration route** (I-6 fix); widget with unique per-instance IDs and `res.ok` guard; camelCase JSON keys. |

---

## Canonical Behaviors (Cross-File Authoritative Definitions)

These behaviors are defined here and must not contradict any phase plan. Phase plans define the _how_; this section defines the _what_.

### Mandatory Cross-Phase Signature Verification Rule

> **Any fix that changes a function signature, constructor, or exported struct MUST include, in the same edit, an explicit list of every other phase file that calls it, confirmation that each was checked, and the updated call site shown in that phase's file — not deferred to a separate pass. A signature change without this cross-reference list attached is considered incomplete, the same way a completion claim without `parity_audit.py` output is considered incomplete.**
>
> This rule exists because two bugs in Round 2 (I-2 and I-7) both occurred because a constructor signature changed in one phase's plan without the corresponding call site in another phase being updated. This is a recurring failure mode, not a coincidence.

### agent_id Parse Failure (finding #1 / #39)

> A malformed or missing `agentId` field on `POST /api/v1/auth/support/login` returns **HTTP 400** with RFC 7807 body `code: "INVALID_AGENT_ID"`. There is **no silent random-UUID fallback** anywhere in the codebase or any plan.

Defined in: `docs/phase_1_plan.md` → Component 1 → `SupportLogin` controller implementation.

**SUPERSEDES** the earlier draft in this document that showed `agentUUID = uuid.New()` on parse failure. That draft was incorrect. The corrected behavior is reject-with-400.

### Revocation Design (finding #28)

There are exactly two revocation features, clearly named:

1. **Per-institution revocation** (`RevokeSupportGrant`): Marks all DB grant rows expired AND writes a Valkey timestamp key `revoked:inst:<institution_id>`. AuthMiddleware rejects any JWT whose `IssuedAt` milliseconds are **strictly less than** (`<`) the stored revocation timestamp. Fails closed if Valkey is unavailable.

2. **Per-agent JWT revocation** (future phase — deferred): Blacklisting a single JWT by `jti` claim. Not implemented in phases 1–7. Tracked as Phase 4.1.

Defined in: `docs/phase_4_plan.md` → Component 1.

### MASTER_ENCRYPTION_KEY

Never hardcoded in any compose or config file. Always read from environment variable `${MASTER_ENCRYPTION_KEY}` which must be set in the operator's `.env` file (see `.env.example` created in Phase 1).

---

## Phase 1: Code-Documentation Parity & Critical Bug Fixes

### 1.1 Fix Support Agent Identity in `SupportLogin`

* **File**: `pkg/controller/auth_dto.go`
* **Change**: Update `SupportLoginInput` DTO. Use **camelCase JSON tags** to match the live codebase convention.

```go
// SupportLoginInput captures support token and agent identity payload.
// agentId parse failure → HTTP 400 INVALID_AGENT_ID (no UUID fallback).
type SupportLoginInput struct {
	Token      string `json:"token" validate:"required"`
	AgentID    string `json:"agentId" validate:"required,uuid"`
	AgentEmail string `json:"agentEmail" validate:"omitempty,email"`
}
```

* **File**: `pkg/controller/auth_support_controller.go`
* **Change**: Reject bad `agentId` with HTTP 400 (not random-UUID fallback).

```go
// agentId parse failure is HTTP 400 — canonical behavior defined here.
agentUUID, err := uuid.Parse(input.AgentID)
if err != nil {
    return NewAppError(http.StatusBadRequest, "INVALID_AGENT_ID", "agentId must be a valid UUID (v4 or v7)")
}
```

### 1.2 Implement Missing `pkg/license` Ed25519 Engine

Full implementation in `docs/phase_1_plan.md` → Component 2.
Key architectural decision: `VerifyAndCache()` is called **once at startup**; `CachedClaims()` is used thereafter. This prevents cliff-edge expiry mid-session and avoids per-request signature verification overhead. `OfflineGraceDays` is applied as a buffer past `ExpiresAt`.

### 1.3 Enforce Strict Valkey Fail-Closed Rule

```go
// Fail hard in production if Valkey is unavailable (valkey-enforcement.md).
if cfg.ValkeyCacheURL != "" {
    valkeyClient, err = cache.NewValkeyClient(cfg.ValkeyCacheURL)
    if err != nil {
        slog.Error("CRITICAL: Failed to connect to Valkey", slog.String("error", err.Error()))
        if cfg.Environment == "production" {
            os.Exit(1)
        }
    }
} else if cfg.Environment == "production" {
    slog.Error("FATAL: VALKEY_CACHE_URL required in production. Exiting.")
    os.Exit(1)
}
```

### 1.4 JWT Key Production Guard

```go
if err := security.LoadJWTKeysFromEnv(); err != nil {
    if cfg.Environment == "production" {
        slog.Error("FATAL: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY required in production. Exiting.")
        os.Exit(1)
    }
    // Development-only fallback:
    security.SetupTestRSAKeys()
}
```

---

## Phase 2: Multi-Database Support & Migrations

### 2.1 Migration Directory Structure

```
migrations/
  postgres/
    000001_create_grantsupport_tables.sql
    000002_add_immutability_triggers.sql
    000003_add_hash_chain_check.sql   ← Applied during Phase 5 deployment ONLY
  mysql/
    000001_create_grantsupport_tables.sql  (CHAR(36) for UUID, TEXT for JSONB)
    000002_add_immutability_triggers.sql   (no DELIMITER — single-statement CREATE TRIGGER)
    000003_add_hash_chain_check.sql        ← Applied during Phase 5 deployment ONLY
  sqlite/
    000001_create_grantsupport_tables.sql  (TEXT for all types)
    000002_immutability_limitation.md      (documented known limitation)
    000003_add_hash_chain_check.sql        ← Applied during Phase 5 deployment ONLY (table rebuild)
```

> **SEQUENCING**: 000003 migrations must NOT be applied before Phase 5 code is deployed. Applying 000003 before Phase 5 causes every `LogSecurityEvent` INSERT to violate the `CHECK (length(hash_chain) > 0)` constraint since Phase 2/3/4 code writes an empty string default.

### 2.2 Multi-Dialect Dynamic DB Driver

* SQLite driver: **`modernc.org/sqlite`** (pure Go — no CGO — compatible with Phase 3 `CGO_ENABLED=0` Dockerfile).
* `DATABASE_DIALECT` env var validated against allowlist `{postgres, mysql, sqlite3}` with clear error on unknown values.

---

## Phase 3: Docker & Deployment Packaging

### 3.1 Dockerfile

Multi-stage build with `CGO_ENABLED=0`, non-root `appuser`, Alpine runtime. Full spec in `docs/phase_3_plan.md`.

### 3.2 Docker Compose

```yaml
# Key corrections vs. earlier draft:
# 1. Mount only migrations/postgres/ into postgres container (not all of migrations/).
# 2. MASTER_ENCRYPTION_KEY via ${MASTER_ENCRYPTION_KEY} env substitution (never hardcoded).
volumes:
  - ../migrations/postgres:/docker-entrypoint-initdb.d
environment:
  - MASTER_ENCRYPTION_KEY=${MASTER_ENCRYPTION_KEY}
```

### 3.3 Upgrade Procedure for Existing Deployments

`docker-entrypoint-initdb.d` only runs on fresh DB volumes. For upgrades, use `golang-migrate`:
```bash
migrate -path migrations/postgres -database "${DATABASE_URL}" up
```

---

## Phase 4: Security Hardening

### 4.1 Two Named Revocation Designs

See Canonical Behaviors section above. Per-institution only in these phases; per-agent JWT deferred.

### 4.2 Atomic Rate Limiter

Uses Lua script (`INCR` + `EXPIRE` in a single atomic operation) instead of two-step approach. Prevents permanent IP ban from TTL-race condition.

### 4.3 Fail-Closed Revocation Check

AuthMiddleware denies (`503`) rather than allows when Valkey is unreachable during revocation check.

### 4.4 Rate Limiter Wired in main.go

```go
r.With(middleware.RateLimitMiddleware(valkeyClient, 10, 60)).
    Post("/api/v1/auth/support/login", controller.CatchAsync(grantController.SupportLogin))
```

---

## Phase 5: Cryptographic Non-Repudiation & Audit PII Redaction

### Step Order (mandatory)
1. Add `field.String("signature").Optional()` to `ent/schema/auditevent.go`
2. Run `go generate ./ent/...`
3. Update `SecurityAuditRepository` constructor and `LogSecurityEvent` signature
4. Update ALL call sites in `grant_support_service.go` and `main.go`

### 5.1 Constructor Change

```go
// Phase 5 changes this from 1-arg to 2-arg. Phase 1 left it unchanged.
// All callers must be updated as part of this phase.
func NewSecurityAuditRepository(base *BaseRepository, privKey ed25519.PrivateKey) *SecurityAuditRepository
```

### 5.2 LogSecurityEvent Change

```go
// Phase 5 drops the *ent.Tx parameter and changes the return type.
// Old: LogSecurityEvent(ctx, instID, actorID, type, desc, *ent.Tx) (*AuditLogResult, error)
// New: LogSecurityEvent(ctx, instID, actorID, type, desc) (*AuditLogResult, error)
//
// P2+P4 fix: ALL 5 call sites are updated in Step 4 of phase_5_plan.md:
//   1. SUPPORT_ACCESS_GRANTED    (line 89  — original)
//   2. SUPPORT_ACCESS_LOGGED_IN  (line 124 — original)
//   3. SUPPORT_ACCESS_REVOKED    (line 151 — original)
//   4. SUPPORT_LOGIN_FAILED      (added by Phase 4 Component 4b)
//   5. SUPPORT_LOGIN_SEAT_LIMIT  (added by Phase 1 Component 5)
// Phase 5 owns patching all of them atomically because it owns the signature change.
```

### 5.3 Signature Canonical Message

Uses `UnixNano()` and includes the event UUID to prevent same-second signature collisions.

---

## Phase 6: Scope, Webhooks & Idempotency

* `InstitutionWebhook` entity for per-institution target URL + shared secret.
* HMAC-SHA256 signing on webhook payloads (header: `X-GrantSupport-Signature`).
* Idempotent event IDs via UUID v5 from `(sourceID + eventType)`.
* `WebhookDispatcher` uses `sync.WaitGroup` and shutdown context (not `context.Background()`).
* `reason` field: present in Ent schema, domain struct, and all layers.
* Scope enforcement deferred to Phase 6.1 (explicitly documented, not silently missing).
* `pkg/encryption` AES-256-GCM package introduced (I-8 fix) — `MASTER_ENCRYPTION_KEY` env var required in production.
* No-retry gap documented: `WebhookDispatcher` makes one delivery attempt; retry logic deferred to Phase 6.1.

> **⚠️ Implementation decision required before coding Phase 6**: `DispatchEvent` accepts a `shutdownCtx context.Context` that must be the **server's shutdown context** — not the HTTP request context. The HTTP request context is cancelled when the handler returns, which would cancel in-flight goroutines and defeat `sync.WaitGroup` safety. Resolution options:
> - **(A — recommended)** Store a `shutdownCtx context.Context` field on `WebhookDispatcher` set at construction time from `main.go`'s shutdown context.
> - **(B)** Use `context.WithoutCancel(ctx)` (requires Go 1.21+) at the call site.
> This must be decided and documented in Phase 6 Component 3 before implementation.

---

## Phase 7: Developer SDK & Client UI

* `MountRoutes` applies `NewAuthMiddleware` to grant/revoke group and `RateLimitMiddleware` to login.
* Widget uses `this.container.querySelector` with unique per-instance UID suffix.
* Widget checks `res.ok` before `res.json()` and wraps in try/catch.
* Widget sends `durationMinutes` (camelCase) to match server DTO.

---

## Verification & Automated Test Plan

### Build Check at Each Phase
```bash
# After Phase 1:
go build ./...

# After Phase 2 (new Ent schema fields + migration SQL):
go generate ./ent/...
go build ./...

# After Phase 5 (ent schema: signature field + code-gen required first):
go generate ./ent/...
go build ./...
# Then deploy code, THEN apply 000003 migration (NOT before):
migrate -path migrations/postgres -database "${DATABASE_URL}" up

# After Phase 6 (new InstitutionWebhook entity):
go generate ./ent/...
go build ./...
```

### Required Environment Variables per Phase

| Phase | Variable | Required In |
|---|---|---|
| 1 | `VALKEY_CACHE_URL` | Production (fatal exit if missing) |
| 1 | `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` | Production (fatal exit if missing) |
| 1 | `LICENSE_KEY`, `LICENSE_PUBLIC_KEY` | Production (seat enforcement disabled if absent) |
| 5 | `AUDIT_SIGNING_PRIVATE_KEY` | Optional; entries unsigned if absent |
| 6 | `MASTER_ENCRYPTION_KEY` | Production (fatal exit if missing; 64 hex chars) |

Generate `MASTER_ENCRYPTION_KEY`: `openssl rand -hex 32`

### Automated Test Suites
1. **Unit & Signature Tests**:
   ```bash
   go test ./pkg/security/... -v
   go test ./pkg/license/... -v
   ```
2. **Controller & Integration Tests**:
   ```bash
   go test ./pkg/service/... -v
   go test ./pkg/controller/... -v
   ```
3. **Container Readiness**:
   ```bash
   docker compose -f docker/docker-compose.yml up --build -d
   curl -i http://localhost:8085/health
   ```

### Manual Verification Flow
1. **Support Grant Creation**: `POST /api/v1/auth/support/grant` with valid admin JWT → `201 Created` with `token`.
2. **Support Agent Login**: `POST /api/v1/auth/support/login` with `{ "token": "...", "agentId": "<valid-uuid>" }` → `200 OK` with `access_token`.
3. **Bad agentId**: `POST /api/v1/auth/support/login` with `agentId: "not-a-uuid"` → `400 INVALID_AGENT_ID`.
4. **Instant Revocation**: `POST /api/v1/auth/support/revoke` → subsequent JWT usage returns `401 TOKEN_REVOKED`.
5. **Valkey down (fail-closed)**: Stop Valkey, present JWT → `503 REVOCATION_CHECK_UNAVAILABLE`.
