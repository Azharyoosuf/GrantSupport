---
trigger: always_on
---

# Unified Architectural Mandates for Go (HOMP)

These non-negotiable rules govern all Go development across Controllers, Routers, Services, and Repositories.

### A. Controller Layer (The Gatekeeper — Go Chi & Validator v10)
- **The "Thin Controller" Mandate**: Controllers handle HTTP I/O ONLY (request decoding, DTO validation, service invocation, HTTP writing). ZERO business logic or direct database queries inside controllers.
- **Zero Boilerplate Error Handling**: Controllers MUST NOT write manual try/catch or verbose error blocks. All handler methods MUST return `error` and be wrapped in the `CatchAsync` higher-order handler function.
- **RFC 7807 Compliance**: All error responses MUST strictly comply with the **Problem Details (RFC 7807)** standard (`type`, `title`, `status`, `detail`, `instance`).
- **Struct-First Validation**: Every request payload MUST be parsed and validated using `DecodeAndValidate[T](r)` with `go-playground/validator/v10` struct tags before calling the Service.
- **Zero ORM in Controllers**: Controllers MUST NEVER import `tenantpro/ent` or `jackc/pgx/v5`.
- **Forced Multi-Tenant Scoping**: Controllers MUST extract `institution_id` from the Auth context (`pkgctx.GetTenant(r.Context())`) and pass it explicitly to every service call.
- **Strict Size Limits**: Individual controller methods MUST NOT exceed 15 lines of code, and single controller files MUST NOT exceed 100 lines of code.

### B. Service Layer (The Orchestrator)
- **Business Logic Ownership**: Contains ALL core business logic, Redlock concurrency locks (`lock.go`), and multi-step transaction orchestrations.
- **Transactional Integrity**: Manages Ent transactions (`r.Transaction(ctx, func(tx *ent.Tx) error)`) for multi-model atomic updates.
- **Zero Direct Ent Queries**: Accesses database models ONLY via Repositories. MUST NOT return raw ORM entities to Controllers (project to DTOs or clean domain structs).
- **Side Effect Governance**: All side effects (WhatsApp alerts, audit logs, notification dispatches) MUST be triggered via `EventEmitter` goroutines or `SecurityAuditService`.

### C. Repository Layer (The Data Access Layer — Ent ORM + pgx/v5)
- **Direct DB Access**: Handles ALL database operations using Ent ORM (`ent/`) for typed CRUD and `pgx/v5` (`pgxpool`) for high-throughput raw SQL aggregations.
- **Mandatory Isolation**: MUST enforce multi-tenant isolation (`institution_id`) for every select, insert, and update query.
- **Standardized Pagination**: "List" endpoints MUST default to 20 records and hard-cap at 100 (`Limit(safeTake)`).
- **Selective Projection**: MUST enforce field selection (`Select(...)`) for security and PII decryption.
- **Valkey Caching**: Query methods wrap results using `cache.CacheWrap` with automatic cache invalidation on write mutations.

### D. The Platinum Guardrails (Non-Negotiable)
- **Multi-Tenancy**: EVERY database query MUST include `institution_id`. No exceptions.
- **Zero-Trust Identity**: 
  - Password Hashing: **Argon2id** (64MB, 3 iterations, 4 parallelism).
  - Session Signing: **RS256 (JWKS)** asymmetric keys.
  - Session Guard: **Refresh Token Rotation (RTR)** enforced via Valkey.
- **Privacy Fortress**: **AWS KMS Envelope Encryption** required for all student/staff PII (including legal name, phone, parent details, and government IDs).
- **Zero-Slop Error Logic**: All API errors must comply with **RFC 7807 (Problem Details)**.
- **Financial Immutability**: **Append-Only Ledgers** with hash-chaining. `DELETE`/`UPDATE` are forbidden on financial tables.
- **Concurrency Shield**: All shared resources (beds, cash) MUST be protected by **Redlock (Distributed Locking)**.
- **Scaling Tier**: Log data > 24 months must be offloaded to **S3 Parquet** (Cold Storage).