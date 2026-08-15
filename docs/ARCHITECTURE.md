# Technical Architecture Specification

This document details the architectural design, component layers, cryptographic primitives, database portability, adapter patterns, and operational trade-offs of **GrantSupport**.

---

## 1. System Overview

GrantSupport operates in two primary deployment topologies:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 STANDALONE HTTP SERVER                                 │
│                                                                                        │
│   HTTP Client (Any Language) ──► Go Chi HTTP Router (:8080)                            │
│                                           │                                            │
│                                           ▼                                            │
│                                 SupportGrantController                                 │
│                                           │                                            │
│                                           ▼                                            │
│                                  GrantSupportService                                   │
│                                     │             │                                    │
│                    ┌────────────────┘             └───────────────┐                    │
│                    ▼                                              ▼                    │
│          SupportGrantRepository                        SecurityAuditRepository         │
│                    │                                              │                    │
│                    ▼                                              ▼                    │
│     Database Layer (PostgreSQL / MySQL / MariaDB / SQLite via Ent ORM & pgx)           │
│                    │                                                                   │
│                    ▼                                                                   │
│     Coordination Adapters (Valkey / Redis / SQL / Memory Stores)                       │
└────────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              EMBEDDED GO IN-PROCESS ENGINE                             │
│                                                                                        │
│   Host Go Application ──► grantsupport.NewEngine(WithDB(db, "postgres"))               │
│                                  │                                                     │
│        ┌─────────────────────────┴─────────────────────────┐                           │
│        ▼                                                   ▼                           │
│   Direct Go Methods (In-Process)                 engine.HTTPHandler()                  │
│   - engine.CreateSupportGrant(...)               - Mounts endpoints on host HTTP mux   │
│   - engine.SupportLogin(...)                                                           │
│   - engine.RevokeSupportGrant(...)                                                     │
│   - engine.VerifyAuditChain(...)                                                       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Layer Responsibilities

### 2.1 Presentation Layer (`pkg/controller/`)
* **Thin Controller Model**: Handlers decode JSON payloads, validate DTO constraints (`go-playground/validator/v10`), invoke domain services, and return responses.
* **RFC 9457 Problem Details**: All errors and validation failures are serialized into standard `application/problem+json` format with correlation IDs.
* **Panic & Error Sanitization**: The `CatchAsync` higher-order wrapper intercepts unhandled panics and errors, logging details server-side via `slog.Error` while returning sanitized messages to clients to prevent internal driver or schema disclosure.

### 2.2 Domain & Service Layer (`pkg/service/`)
* **`GrantSupportService`**: Orchestrates token creation, atomic claim validation, duration bounds, IP restriction matching, and audit event dispatching.
* **Token Version Invalidation**: Coordinates session revoking by incrementing token version counters in the configured `RevocationStore`.
* **Asynchronous Webhook Triggering**: Emits signed webhook events via bounded background worker pools.

### 2.3 Data Access Layer (`pkg/repository/`)
* **`SupportGrantRepository`**: Typed CRUD operations over `gs_support_grants` table with strict multi-tenant `institution_id` filtering.
* **`SecurityAuditRepository`**: Chained append-only audit event logging to `gs_audit_events` with SHA-256 hash chaining and transaction management.
* **Database Drivers**: Reference support for PostgreSQL 16+ via `jackc/pgx/v5`, MySQL 8.4+ and MariaDB 11.4+ via standard Go relational drivers, and SQLite 3 via pure Go `modernc.org/sqlite`.

### 2.4 Capability Adapters (`pkg/adapters/`)
Implements capability interfaces defined in `pkg/ports/`:
* **`LockStore`**: `RedisLockStore` (Redlock atomic `SETNX` + Lua release) and `SQLLockStore` (database-level transactional/advisory locking).
* **`RevocationStore`**: `RedisRevocationStore` (Valkey key-value version cache) and `SQLRevocationStore` (table-backed version query).
* **`RateLimiterStore`**: `RedisRateLimiter` (atomic Lua token bucket per client IP) and `MemoryRateLimiter` (in-memory sliding window).

---

## 3. Delegation Token & Session Lifecycle

```
[Customer Admin]                                             GrantSupport                                             [Support Agent]
       │                                                           │                                                         │
       │── 1. POST /grant (duration: 60m, scope, IPs) ────────────►│                                                         │
       │                                                           ├── 2. Generate 256-bit crypto/rand token                 │
       │                                                           ├── 3. Hash token: SHA-256(rawToken)                      │
       │                                                           ├── 4. Insert grant record (is_used=false)                │
       │                                                           ├── 5. Append SUPPORT_ACCESS_GRANTED audit event          │
       │                                                           └── 6. Dispatch async webhook 'grant.created'             │
       │◄── 7. Return raw token (once; never stored) ──────────────┤                                                         │
       │                                                           │                                                         │
       │ [Secure Out-of-Band Delivery to Agent]                    │                                                         │
       │                                                           │                                                         │
       │                                                           │◄── 8. POST /login (token, agentId) ─────────────────────│
       │                                                           ├── 9. Verify client IP against whitelist                 │
       │                                                           ├── 10. Query grant by SHA-256(token)                     │
       │                                                           ├── 11. Atomic CAS UPDATE (is_used=true WHERE is_used=f)  │
       │                                                           ├── 12. Issue RS256 JWT (exp = grant.ExpiresAt)           │
       │                                                           ├── 13. Append SUPPORT_ACCESS_LOGGED_IN audit event       │
       │                                                           └── 14. Dispatch async webhook 'grant.claimed'            │
       │                                                           │─── 15. Return RS256 Access Token ──────────────────────►│
       │                                                           │                                                         │
       │                                                           │◄── 16. POST /logout (voluntary) ────────────────────────│
       │                                                           ├── 17. Increment agent token version in RevocationStore  │
       │                                                           └── 18. Return 200 OK ───────────────────────────────────►│
       │                                                           │                                                         │
       │── 19. POST /revoke (admin force revoke) ─────────────────►│                                                         │
       │                                                           ├── 20. Expire all pending unredeemed grants in DB        │
       │                                                           ├── 21. Bump agent token versions in RevocationStore      │
       │                                                           ├── 22. Append SUPPORT_ACCESS_REVOKED audit event         │
       │                                                           └── 23. Dispatch async webhook 'grant.revoked'            │
       │◄── 24. Return 200 OK ─────────────────────────────────────┤                                                         │
```

---

## 4. Authentication Mechanisms

### 4.1 Default: RS256 JWT Bearer Authentication
Standard for the HTTP API:
* **Asymmetric RS256 Signing**: Tokens are signed using a private RSA key (`JWT_PRIVATE_KEY`) and verified using the corresponding public key (`JWT_PUBLIC_KEY`).
* **Active Revocation Verification**: The `NewAuthMiddleware` extracts `token_version`, `institution_id`, and `user_id` from JWT claims and queries the `RevocationStore`. If the current version in the store exceeds the JWT's version, the request is rejected with HTTP 401 `TOKEN_REVOKED`.
---

### 3.2 Just-In-Time (JIT) Access Request & Customer Approval Lifecycle

GrantSupport provides an optional, in-band request and approval state machine:

```
[Support Agent]                                                GrantSupport                                              [Customer Admin]
       │                                                             │                                                          │
       │── 1. POST /access-requests (reason, duration, scope) ──────►│                                                          │
       │                                                             ├── 2. Persist in gs_access_requests (status='PENDING')    │
       │                                                             ├── 3. Append 'access_request.created' audit event         │
       │                                                             └── 4. Dispatch async webhook 'access_request.created'     │
       │◄── 5. Return Created AccessRequest (201 Created) ───────────┤                                                          │
       │                                                             │                                                          │
       │                                                             │◄── 6. GET /access-requests (views pending requests) ─────│
       │                                                             │                                                          │
       │                                                             │◄── 7. POST /access-requests/{id}/approve ────────────────│
       │                                                             │    (Check: approver_id != requester_id)                  │
       │                                                             │    (BEGIN DB TRANSACTION)                                │
       │                                                             │    ├── Atomic CAS: status='APPROVED', expires_at > now   │
       │                                                             │    ├── Insert SupportGrant record (SHA-256 token hash)   │
       │                                                             │    └── Append 'access_request.approved' audit event      │
       │                                                             │    (COMMIT DB TRANSACTION)                               │
       │                                                             │    └── Dispatch async webhook 'access_request.approved'  │
       │                                                             │─── 8. Return rawToken once in HTTP response ────────────►│
       │                                                             │       (Admin shares rawToken via secure channel)         │
       │                                                             │                                                          │
       │◄── 9. Agent receives token out-of-band / via ticket ────────┴──────────────────────────────────────────────────────────┘
       │
       │── 10. POST /auth/support/login (token, agentId) ───────────► [Same single-use redemption and JWT issuance]
```

---

## 4. Authentication, Session Revocation & Key Security

### 4.1 Inbound JWT Bearer Authentication (Standard REST API)
* **Bearer Validation**: Validates RS256 signatures against public keys in `KeyManager` with `kid` tracking.
* **Revocation Check**: Queries `RevocationStore.IsTokenRevoked(instID, userID, tokenVersion)` on every request.
* **Fail-Closed Guard**: If the `RevocationStore` is nil or unreachable, the middleware rejects requests with HTTP 503 `REVOCATION_CHECK_UNAVAILABLE`.

### 4.2 Opt-In: BulletproofAuth (5-Layer Ed25519 Request Signing)
Available via `engine.BulletproofMiddleware(keyStore)` for Go embedders securing machine-to-machine integrations:
1. **Layer 1**: Ed25519 asymmetric cryptographic signature over canonical request payload (`Method\nPath\nNonce\nExpiresAt\nBody`).
2. **Layer 2**: Client-specified payload expiration (TTL <= 900s) with 30s clock skew window.
3. **Layer 3**: Nonce replay attack protection via atomic cache store.
4. **Layer 4**: Socket-level TCP / trusted proxy client IP binding.
5. **Layer 5**: Multi-tenant context injection into request context.

---

## 5. Audit Trail Integrity & Hash Chaining

The `gs_audit_events` table maintains a chronological cryptographic ledger:

```
Event #1 ──► Hash_1 = SHA-256(Event_1_Data)
                │
Event #2 ──► Hash_2 = SHA-256(Hash_1 + Event_2_Data)
                │
Event #3 ──► Hash_3 = SHA-256(Hash_2 + Event_3_Data)
```

* **Sequential Binding**: Each event record stores `previous_hash` and `hash_chain`.
* **Tamper Verification**: `engine.VerifyAuditChain(ctx, institutionID)` recalculates all hashes chronologically. If any record was altered, deleted, or inserted out of order, verification fails.
* **Concurrency Protection**: Per-tenant mutex striping ensures concurrent operations within the same tenant do not interleave hash calculations.

---

## 6. Known Architectural Trade-offs & Limitations

### 6.1 Absence of CORS (By Design)
GrantSupport does not include Cross-Origin Resource Sharing (CORS) middleware. The intended architectural pattern is:

```
Browser Client (Admin Dashboard)
       │
       ▼
Host Application Backend (Proxy / BFF)
       │
       ▼
GrantSupport API (Internal Network / VPC)
```
Direct browser calls to GrantSupport are discouraged to avoid exposing administrative credential delegation endpoints to cross-origin web scripts.

### 6.2 Fail-Closed Valkey Availability Dependency
* **Startup**: If Valkey is omitted from configuration, the server gracefully initializes SQL-backed and in-memory fallback stores.
* **Mid-Operation**: If Valkey is configured and subsequently becomes unreachable during active operation, security-critical paths (rate limiting on `/login` and revocation checks) **fail closed** with HTTP 503. The system intentionally does not silently downgrade to in-memory stores during a request to prevent distributed rate limit bypasses.

### 6.3 Scope Enforcement Boundary
The `scope` parameter (e.g. `BILLING_ONLY`, `READ_ONLY`, `FULL_ACCESS`) is passed through and embedded as a claim in the issued JWT. GrantSupport **does not interpret or enforce application domain permissions**. The host application must inspect the JWT `scope` claim to restrict access.

### 6.4 Asynchronous Webhook Delivery
Outbound HTTP webhooks are dispatched asynchronously using bounded goroutine workers. Network timeouts or failures at the webhook receiver are logged as warnings and do not abort or roll back database grant transactions.

### 6.5 Token Delivery Channel Limitation
Approval controls whether access may be granted. GrantSupport does not provide a messaging channel for transferring the resulting bearer credential. The host organization is responsible for securely relaying the one-time token through its existing trusted operational channel. GrantSupport deliberately does not include email, SMS, Slack, or ticketing infrastructure.
