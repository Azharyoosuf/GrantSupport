# GrantSupport 🛡️

**Source-Available Delegated Support-Access Authentication & Cryptographic Audit Engine**

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](LICENSE)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1.0-green.svg)](api/openapi.yaml)

GrantSupport solves the **"vendor support access problem"** for multi-tenant B2B SaaS platforms. Rather than creating permanent backdoors or sharing static credentials, GrantSupport allows customer administrators to delegate temporary, time-bounded, cryptographically signed, and tamper-audited access to vendor support engineers.

---

## 🔒 Core Security & Architectural Guarantees

1. **Two-Tier Authentication**:
   - **Tier 1 (Grant Creation & Revocation)**: Protected by standard RS256 Bearer JWTs (`ADMIN` / `OPERATOR` roles). Revoking a grant prevents unredeemed tokens from being claimed.
   - **Tier 2 (Grant Consumption)**: Support agents claim high-entropy single-use tokens, issuing a 4-hour `SUPPORT_AGENT` RS256 JWT with explicit tenant scoping. (An already-issued support session has its own JWT lifetime and is governed by JWT expiration and revocation store mechanisms).
2. **Atomic Single-Use Consumption**:
   - Unconditional SQL conditional predicate (`UPDATE ... WHERE id = ? AND is_used = false`) prevents concurrent token double-claim race conditions across distributed instances.
3. **Cryptographic SHA-256 Audit Ledger**:
   - Every grant lifecycle event is recorded in a cryptographically chained, tamper-evident, append-only ledger with SHA-256 hash-chaining.
   - **Per-Institution Mutex Striping**: Prevents hash-chain interleaving under high concurrency while avoiding cross-tenant lock contention.
   - **Tamper Verification**: Built-in `VerifyAuditChain(ctx, institutionID)` detects any unauthorized database mutation.
4. **Automated PII & Credential Sanitization**:
   - Redacts bearer tokens, passwords, credit cards (PAN), emails, and phone numbers before logging to the tamper-evident audit ledger.
5. **Database Portability & Connection Pool Preservation**:
   - **PostgreSQL**: Reference / primary production database.
   - **MySQL (8.0+) & MariaDB (10.5+)**: Supported enterprise relational backends.
   - **SQLite**: Supported for single-process, embedded applications, local development, and test suites (pure Go `modernc.org/sqlite`; not distributed across multi-container replicas).
   - Reuses caller-managed `*sql.DB` connection pools without creating secondary pools or leaking resources.
6. **Valkey / Redis Optionality**:
   - Distributed locking, replay prevention, and token revocation officially support **Valkey** and **Redis** (other Redis-protocol-compatible implementations may work but are not officially verified or supported).
   - Operates fully without Redis/Valkey by automatically falling back to SQL database tables or in-process memory stores. Rate limiting without Redis operates on an in-memory token bucket per instance.
7. **Signed Lifecycle Webhooks**:
   - Dispatches `grant.created`, `grant.claimed`, and `grant.revoked` webhook events with HMAC-SHA256 request signatures (`X-GrantSupport-Signature`).
8. **Opt-In 5-Layer Machine-to-Machine Security (Go Embedders)**:
   - Provides an optional 5-layer Ed25519 dual-key middleware (`engine.BulletproofMiddleware(keyStore)`) for Go embedders building custom machine-to-machine routes (timestamp freshness, nonce replay protection, Ed25519 signatures, and IP CIDR binding).
   - *Note*: This is an **opt-in capability** for custom routes and is NOT applied to default HTTP endpoints (which use standard JWT bearer authentication and rate limiting). Callers must provide and manage their own key storage.
9. **Data Encryption & Key Management Capabilities**:
   - Provides optional AWS KMS envelope encryption and local HKDF AES-256-GCM encryption utilities for application-level data protection; encryption is not automatically applied to every database field.

---

## 🚀 Quickstart

### Option 1: Embedded Go Library (Zero-Infra In-Process Engine)

GrantSupport can be embedded directly inside any Go service:

```go
package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
	"grantsupport/pkg/grantsupport"
)

func main() {
	db, _ := sql.Open("sqlite", "file:app.db?cache=shared&_pragma=foreign_keys(1)")

	// Initialize GrantSupport embedded engine
	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		log.Fatalf("Failed to initialize GrantSupport: %v", err)
	}
	defer engine.Close()

	// Direct Go API Usage:
	// rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "BILLING_ONLY", nil)
	// instID, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
	// valid, err := engine.VerifyAuditChain(ctx, instID)

	// Mount REST Endpoints on existing HTTP Server:
	http.Handle("/api/v1/", engine.HTTPHandler())
	http.ListenAndServe(":8080", nil)
}
```

---

### Option 2: Standalone Microservice via Docker Compose

Run GrantSupport with PostgreSQL and Valkey:

```bash
docker compose --profile default up -d
```

Or run with SQLite in-container storage:

```bash
docker compose --profile sqlite up -d
```

---

## 📡 REST API Reference

The full interactive OpenAPI 3.1 specification is available in [`api/openapi.yaml`](api/openapi.yaml).

### 1. Create Support Grant (Customer Admin)
```http
POST /api/v1/auth/support/grant
Authorization: Bearer <Admin_JWT>
Content-Type: application/json

{
  "durationMinutes": 60,
  "scope": "READ_ONLY",
  "whitelistedIps": ["198.51.100.4"]
}
```
**Response (201 Created):**
```json
{
  "success": true,
  "message": "Support access token generated successfully.",
  "token": "550e8400-e29b-41d4-a716-446655440000_9f83a8b9487c6e12e2057639f28d8442..."
}
```

---

### 2. Support Login (Support Agent)
```http
POST /api/v1/auth/support/login
Content-Type: application/json

{
  "token": "550e8400-e29b-41d4-a716-446655440000_9f83a8b9487c6e12e2057639f28d8442...",
  "agentId": "7f4c935b-16d7-4f9e-a8f2-39c4a852b719"
}
```
**Response (200 OK):**
```json
{
  "success": true,
  "message": "Support agent authenticated successfully.",
  "institution_id": "550e8400-e29b-41d4-a716-446655440000",
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 3. Revoke Active Grants (Customer Admin)
```http
POST /api/v1/auth/support/revoke
Authorization: Bearer <Admin_JWT>
```
**Response (200 OK):**
```json
{
  "success": true,
  "message": "All active support access grants revoked successfully."
}
```

> **Note on Revocation Semantics**: Revoking a support grant immediately invalidates all unredeemed grants for the tenant, preventing future claims. An already-issued support session has its own JWT lifetime and is governed by standard JWT expiration and `RevocationStore` session revocation mechanisms.

---

## 🧪 Testing & Verification

Run the entire comprehensive test suite across all capability adapters, concurrent race simulations, and cryptographic verifications:

```bash
go test -count=1 ./... -v
```

---

## 📄 License & Commercial Terms

GrantSupport is licensed under the **[Business Source License 1.1 (BSL 1.1)](LICENSE)**.

- **Free Tier**: Free of charge for personal use, educational use, non-commercial projects, evaluation, development, testing, and production use by individuals and small organizations.
- **Commercial / Enterprise Tier**: Production use of GrantSupport by commercial corporations, enterprises, or multinational corporations (MNCs) requires a paid commercial license (**$199/month**) obtained directly from the Licensor.
- **Open Source Transition**: On **August 14, 2030** (Change Date), the software automatically converts to the **Apache License, Version 2.0**.

For commercial licensing inquiries: `licensing@grantsupport.io` (or repository maintainer).
