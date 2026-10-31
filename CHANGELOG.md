# Changelog

All notable changes to GrantSupport will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security
- **Untrusted Client IP Spoofing via `chimiddleware.RealIP` (present in `v0.1.0-beta.3`)**: Removed `chimiddleware.RealIP` from both the standalone server router (`cmd/server/main.go`) and the embedded engine router (`pkg/grantsupport/engine.go`). Previously, `chimiddleware.RealIP` unconditionally overwrote `r.RemoteAddr` from `True-Client-IP`, `X-Real-IP`, or `X-Forwarded-For` before `security.ExtractClientIP` could verify the peer against `TRUSTED_PROXIES`, allowing direct untrusted peers to spoof client IPs to bypass per-grant `whitelisted_ips` checks at login and per-IP rate limiting.

### Removed
- **Extracted BulletproofAuth into Standalone Repository (`000006_drop_replays`)**: Extracted the `BulletproofAuth` Ed25519 request-signing middleware, `ReplayStore` port/adapters (`pkg/ports/replay.go`, `pkg/adapters/replay/`), `pkg/security/keys.go`, `Engine.BulletproofMiddleware`, `WithReplayStore`, and the `ENFORCE_STRICT_IP_BINDING` / `EnforceStrictIPBinding` configuration option into the standalone Go repository [`github.com/azharyoosuf/bulletproofauth`](https://github.com/azharyoosuf/bulletproofauth) (`/Users/azrusf/Personal_Projects/bulletproofauth`). Added migration `000006_drop_replays` across PostgreSQL, MySQL, MariaDB, and SQLite to drop the `gs_replays` table.
- **Removed JIT Access-Request Subsystem**: Removed the in-band JIT access-request and approval feature introduced in `v0.1.0-beta.3` (`/api/v1/access-requests*` endpoints, `AccessRequest` domain/schema/service/controllers, and `access_request.*` audit/webhook events) to consolidate grant issuance onto the single direct delegation path (`POST /api/v1/auth/support/grant`). Approval and ticketing workflows belong in the host application, which calls `POST /api/v1/auth/support/grant` once a request is approved.
- **Database Migration `000004_drop_access_requests`**: Migration `000004` drops the `gs_access_requests` table (and its indexes) across PostgreSQL, MySQL, MariaDB, and SQLite. **Upgrade Note**: Operators upgrading from `v0.1.0-beta.3` with pending access requests should resolve or export them before applying migration `000004`.

### Fixed
- **Audit Chain Verification Status & Error Sanitization**: `POST /api/v1/audit/verify` now distinguishes hash-chain tampering (`repository.ErrAuditChainIntegrityViolation`) from database query failures, returning HTTP `200 OK` with `{"valid": false}` on broken chains and generic HTTP `500` without leaking raw error details on database failures. Sanitized `GET /health/ready` `503` responses so raw database/Valkey driver error strings are logged server-side rather than concatenated into client responses.
- **Session Termination Not-Found Status**: Mapped `repository.ErrGrantNotFound` in `DELETE /api/v1/auth/support/sessions/{grantId}` to HTTP `404 Not Found` (`GRANT_NOT_FOUND`) instead of HTTP `500`.
- **Embedded Engine Parity (`WithRedis`, Security Headers, Webhooks)**: Added `grantsupport.WithRedis` (and updated `NewEngine`) so providing a Redis/Valkey client wires `RedisLockStore`, `RedisRevocationStore`, and `RedisRateLimiter` by default unless overridden by explicit store options; mounted `SecurityHeadersMiddleware` in `Engine.HTTPHandler()`; and guarded `WebhookDispatcher` startup on both `WebhookURL` and `WebhookSecret` being non-empty.
- **Optional `VALKEY_CACHE_URL` Default**: Left `ValkeyCacheURL` empty when `VALKEY_CACHE_URL` is unset in `config.LoadConfig()` instead of defaulting to `redis://127.0.0.1:6379`, ensuring SQL-only deployments do not dial `127.0.0.1:6379` at startup.
- **Concurrent Grant Creation Contention**: Removed the unnecessary per-institution distributed lock around single-row `INSERT` in `GrantSupportService.CreateSupportGrantScoped` (and removed unused `lockStore` from `GrantSupportService`), preventing concurrent grant creations for the same institution from failing with `LOCK_BUSY`.
- **Atomic Redis Rate Limiter TTL**: Replaced separate `INCR` and `EXPIRE` commands in `RedisRateLimiter.Allow` with an atomic Lua script (`INCR` + `PEXPIRE`) that guarantees every counter has a positive TTL and repairs any pre-existing key lacking a TTL.
- **MariaDB `whitelisted_ips` CHECK Constraint Normalization (`000005_normalize_whitelisted_ips_check`)**: Normalized `gs_support_grants.whitelisted_ips` on MariaDB from `CHECK (whitelisted_ips IS NULL OR JSON_VALID(whitelisted_ips))` to `CHECK (json_valid(whitelisted_ips))` so MariaDB users with `AUTO_MIGRATE` enabled no longer crash at startup on `gs_support_grants` (`Error 1091: Can't DROP CONSTRAINT whitelisted_ips`).
- **RFC 9457 Problem Details `type` URN**: Changed the default `"type"` value in RFC 9457 `application/problem+json` error responses from `https://grantsupport.io/errors/<code>` to `urn:grantsupport:error:<code>`.

---

## [0.1.0-beta.3] - 2026-08-15

### Delegated Support Access Approval Workflow

#### JIT Access Requests & Customer Approval
- **In-Band Access Requests**: Added `POST /api/v1/access-requests` allowing vendor support agents to submit structured Just-In-Time access requests specifying reason, requested duration, requested scope, and optional IP whitelist.
- **Customer Admin Review & Approval**: Added `POST /api/v1/access-requests/{id}/approve` enabling customer administrators to approve requests, atomically creating a `SupportGrant` and returning the single-use `rawToken` exactly once in the response body.
- **Self-Approval Prohibition**: Strictly enforced `requester_id != approver_id`. Agents attempting to self-approve receive HTTP 403 Problem Details `SELF_APPROVAL_FORBIDDEN`.
- **Rejection & Cancellation**: Added `POST /api/v1/access-requests/{id}/reject` (admin denial with reason) and `POST /api/v1/access-requests/{id}/cancel` (agent or admin cancellation).
- **Access Request Listing & Inspection**: Added `GET /api/v1/access-requests` and `GET /api/v1/access-requests/{id}` with strict tenant isolation. Support agents view only their own requests.
- **Lazy Expiration Model**: Pending access requests automatically expire after 24 hours via lazy dynamic status evaluation and conditional SQL predicates without requiring background scheduler daemons.
- **Token Delivery Boundary**: Documented that GrantSupport intentionally returns the raw bearer credential once to the approving administrator, without storing unhashed tokens or providing notification/email delivery infrastructure.

#### Database Migrations & Multi-Dialect Support
- **New Table `gs_access_requests`**: Created additive schema migration `000003_add_access_requests.up.sql` across PostgreSQL, MySQL, MariaDB, and SQLite.
- **Atomic Database Transactions**: Wrapped approval CAS state transitions, grant generation, and audit logging into a single database transaction boundary.

---

## [0.1.0-beta.2] - 2026-08-15

### Operational Observability, Key Lifecycle & Event Resilience

#### Security & Key Lifecycle
- **Strict Key Selection & Rotation**: Implemented `KeyManager` supporting active primary signing keys and transitional verification keys with `kid` tracking. Token verification strictly fails closed (HTTP 401 Problem Details `INVALID_TOKEN_SIGNATURE`) on unknown `kid` headers with zero fallback to the primary key.
- **Legacy Token Compatibility**: Maintained backward-compatibility fallback for legacy JWTs lacking a `kid` header using explicitly configured legacy verification keys.
- **RFC 7517 JWKS Key Identification**: Enhanced `GET /.well-known/jwks.json` to serialize the `kid` parameter across all active and transitional public keys.

#### Scope Evaluation
- **Pure-Go Deterministic Scope Matcher**: Introduced `pkg/scope` providing `Matches`, `Contains`, and `ParseScopes` with hierarchical terminal wildcard (`foo:*`), exact match, and global wildcard (`*`) support. Non-terminal wildcards (`foo:*:bar`) are strictly rejected. Scope matching remains purely an optional utility and does not alter core JWT authorization.

#### Observability & Health Monitoring
- **Prometheus Operational Metrics Scraper**: Added native, pull-only `GET /metrics` exporting low-cardinality counters, gauges, and request histograms with strict privacy guardrails (zero PII, zero tenant UUIDs, zero token hashes, zero raw URLs).
- **Process Liveness Probe**: Added `GET /health/live` for instantaneous container liveness checks.
- **Adaptive Dependency Readiness Probe**: Added `GET /health/ready` verifying SQL database connectivity and optional Valkey connectivity (SQL-only mode reports healthy without requiring Valkey).

#### Event Resilience & Worker Durability
- **Bounded In-Memory Webhook Retries**: Enhanced `WebhookDispatcher` with a hard queue capacity of 5,000 events, 3-attempt exponential backoff (1s, 5s, 15s), dead-letter warning logging, and graceful drain on shutdown. Documented ephemeral in-memory durability boundaries.

---

## [0.1.0-beta.1] - 2026-08-15

### Initial Public Beta Release (MIT)

#### Community & Open-Source Relicensing
- **Relicensed to MIT**: Formally transitioned GrantSupport to the permissive MIT License as a pure open-source, community-driven project.
- **Removed Commercial Model Artifacts**: Completely eliminated all commercial licensing parameters, BSL limits, and subscription documentation.
- **Added Community Assets**: Introduced Contributor Covenant Code of Conduct, GitHub issue templates for bug reports and feature requests, and pull request verification templates.

#### Core Engine Features
- **Public JWKS Distribution**: Added `GET /.well-known/jwks.json` serving standard RFC 7517 JSON Web Key Sets for downstream API gateways and microservices to dynamically verify RS256 JWT signatures.
- **Active Session Management**: Added `GET /api/v1/auth/support/sessions` and `DELETE /api/v1/auth/support/sessions/{grantId}` to list active delegated support sessions and perform targeted session termination.
- **Cryptographic Audit Ledger REST APIs**: Exposed `GET /api/v1/audit/events` (with pagination, actor, and event type filtering) and `POST /api/v1/audit/verify` (cryptographic SHA-256 chain verification) over HTTP.
- **Delegated Support Access**: High-entropy single-use delegation tokens (`{tenant_id}_{rand32}`) with atomic CAS redemption and dynamic duration-matched RS256 JWT sessions.
- **Cryptographic Audit Ledger**: Append-only SHA-256 hash-chained security event audit logging with distributed lock serialization and built-in chain verification (`VerifyAuditChain`).
- **Multi-Database Support**: Verified native compatibility across PostgreSQL 16, MySQL 8.4, MariaDB 11.4, and pure-Go SQLite 3.
- **Valkey / Redis Optionality**: Distributed locking, replay nonces, and session revocation support Valkey with zero-dependency SQL fallbacks.
- **Fail-Closed Revocation & Rate Limiting**: Security-sensitive operations fail closed with HTTP 503 if downstream stores become unavailable during active operations. Applied rate limiting to `/grant` and `/revoke`.
- **Security Hardening**:
  - Enforced client IP whitelist matching in `SupportLogin`.
  - Added `/api/v1/auth/support/logout` for voluntary support agent session termination.
  - Sanitized error details across all HTTP controllers to prevent internal database driver disclosure.
  - Signed lifecycle webhooks with HMAC-SHA256 request signatures.

---

## [1.0.0] - 2026-08-14

### Initial Release (Historical: BSL 1.1)

#### Core Features
- Initial prototype release under Business Source License 1.1 prior to open-source community relicensing.
