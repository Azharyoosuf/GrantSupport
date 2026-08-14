# GrantSupport 🛡️

**Source-Available Delegated Support-Access Authentication & Cryptographic Audit Engine**

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](LICENSE)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1.0-green.svg)](api/openapi.yaml)

GrantSupport solves the **"vendor support access problem"** for multi-tenant B2B SaaS platforms. Rather than creating permanent backdoors or sharing static credentials, GrantSupport allows customer administrators to delegate temporary, time-bounded, cryptographically signed, and tamper-audited access to vendor support engineers.

---

## 🔒 Core Security & Architectural Guarantees

1. **Two-Tier Authentication & Dynamic Session Lifetime**:
   - **Tier 1 (Grant Creation & Revocation)**: Protected by standard RS256 Bearer JWTs (`ADMIN` / `OPERATOR` roles).
   - **Tier 2 (Grant Consumption)**: Support agents claim high-entropy single-use tokens, issuing an RS256 `SUPPORT_AGENT` JWT with explicit tenant scoping whose lifetime **strictly matches the requested grant duration** (`session expiration <= grant expiration`).
2. **Atomic Single-Use Consumption**:
   - Unconditional SQL conditional predicate (`UPDATE gs_support_grants SET is_used = true, used_at = ... WHERE id = ? AND is_used = false`) prevents concurrent token double-claim race conditions across distributed instances.
3. **Cryptographic SHA-256 Tamper-Evident Audit Ledger**:
   - Every grant lifecycle event is recorded in a cryptographically chained, append-only ledger with SHA-256 hash-chaining and canonical microsecond timestamps.
   - **Per-Institution Mutex Striping & Distributed Locking**: Prevents hash-chain interleaving under high concurrency while avoiding cross-tenant lock contention.
   - **Tamper Verification**: Built-in `VerifyAuditChain(ctx, institutionID)` detects unauthorized database modifications or row deletions.
4. **Dual Grant and Active Session Revocation**:
   - `POST /api/v1/auth/support/revoke` invalidates all unredeemed grants AND immediately revokes all currently active `SUPPORT_AGENT` JWT sessions via token-version tracking.
   - `POST /api/v1/auth/support/logout` allows support agents to invalidate their active JWT session upon completing maintenance.
5. **Automated PII & Credential Sanitization**:
   - Automatically redacts bearer tokens, passwords, credit cards (PAN), emails, and phone numbers before logging to the tamper-evident audit ledger.
6. **Database Portability & Connection Pool Preservation**:
   - **PostgreSQL 16+**: Reference and primary production database (`jackc/pgx/v5`).
   - **MySQL 8.4 LTS & MariaDB 11.4 LTS**: Enterprise relational backends (`go-sql-driver/mysql`).
   - **SQLite 3**: Embedded applications, local development, and test suites (pure Go `modernc.org/sqlite`).
   - Reuses caller-managed `*sql.DB` connection pools without creating secondary pools or leaking resources.
7. **Valkey / Redis Support**:
   - Distributed locking, replay prevention, and token revocation support **Valkey 7.2 LTS** (`valkey://`, `valkeys://`) and **Redis 7.x** (`redis://`, `rediss://`).
   - Operates fully without Redis/Valkey by automatically falling back to SQL database tables or in-process memory stores.
8. **Signed Lifecycle Webhooks**:
   - Dispatches `grant.created`, `grant.claimed`, and `grant.revoked` webhook events with HMAC-SHA256 request signatures (`X-GrantSupport-Signature`).
9. **Data Encryption Capabilities**:
   - Provides optional AWS KMS envelope encryption (`aws-sdk-go-v2/service/kms`) and local HKDF AES-256-GCM encryption utilities for application-level data protection.
10. **Production HTTPS & Transport Security**:
   - Supports native TLS termination with `MinVersion: tls.VersionTLS12`, modern ECDHE cipher suites, HTTP/2 ALPN (`h2`), HSTS, and slow-client resource exhaustion timeouts (`ReadHeaderTimeout: 5s`), alongside trusted reverse-proxy deployment modes.

---

## 📊 Empirically Verified Performance Benchmarks

Measured on a 64-bit Linux AMD64 environment (12th Gen Intel Core i5-12450H):

| Layer / Operation | Target Backend | Throughput | p50 Latency | p95 Latency | Error Rate |
|---|---|---:|---:|---:|---:|
| **In-Memory JWT Verification** | RS256 Public Key (2048-bit) | ~36,000 ops/s | 27.5 µs | 28.7 µs | 0.0% |
| **In-Memory JWT Signing** | RS256 Private Key (2048-bit) | ~1,560 ops/s | 638.0 µs | 642.0 µs | 0.0% |
| **Token Version Check** | Valkey 7.2 (Live Socket) | 18,665 req/s | 45.2 µs | 101.2 µs | 0.0% |
| **Rate Limiter Check** | Valkey 7.2 (Lua Token Bucket) | 8,554 req/s | 52.4 µs | 326.9 µs | 0.0% |
| **Create Support Grant** | PostgreSQL 16 (Live Network) | 127.4 req/s | 7.1 ms | 10.2 ms | 0.0% |
| **Support Login (Full Pipeline)** | PostgreSQL 16 (Live Network) | 88.2 req/s | 10.8 ms | 14.5 ms | 0.0% |
| **Revocation Check (SQL)** | PostgreSQL 16 (Live Network) | 1,114.7 req/s | 0.82 ms | 1.21 ms | 0.0% |
| **HTTP `POST /grant`** | End-to-End HTTP Loopback | 750.6 req/s | 1.03 ms | 3.21 ms | 0.0% |
| **HTTP `POST /login`** | End-to-End HTTP Loopback | 385.0 req/s | 2.46 ms | 4.12 ms | 0.0% |

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

Run GrantSupport with PostgreSQL 16 and Valkey 7.2:

```bash
docker compose --profile default up -d
```

Or run with MySQL 8.4:

```bash
docker compose --profile mysql up -d
```

Or run with MariaDB 11.4:

```bash
docker compose --profile mariadb up -d
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
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 3. Revoke Support Access (Customer Admin)
```http
POST /api/v1/auth/support/revoke
Authorization: Bearer <Admin_JWT>
```
**Response (200 OK):**
```json
{
  "success": true,
  "message": "All support delegations revoked successfully."
}
```
*Note: This operation immediately expires all unredeemed grant tokens for the tenant AND revokes all active `SUPPORT_AGENT` JWT sessions in the revocation store.*

---

### 4. Support Logout (Support Agent)
```http
POST /api/v1/auth/support/logout
Authorization: Bearer <Support_Agent_JWT>
```
**Response (200 OK):**
```json
{
  "success": true,
  "message": "Support agent session logged out successfully."
}
```

---

## 🧪 Testing & Verification

Run the comprehensive test suite across all capability adapters, concurrency race simulations, and cryptographic verifications:

```bash
go test -count=1 -v ./...
```

Run race detector in Linux:

```bash
CGO_ENABLED=1 go test -race -count=1 ./...
```

---

## 📄 License & Commercial Terms

GrantSupport is licensed under the **[Business Source License 1.1 (BSL 1.1)](LICENSE)**.

- **Free Tier**: Free of charge for personal use, educational use, non-commercial projects, evaluation, development, testing, and production use by individuals and small organizations.
- **Commercial / Enterprise Tier**: Production use of GrantSupport by commercial corporations, enterprises, or multinational corporations (MNCs) requires a paid commercial license (**$199/month**) obtained directly from the Licensor.
- **Open Source Transition**: On **August 14, 2030** (Change Date), the software automatically converts to the **Apache License, Version 2.0**.

For commercial licensing inquiries: `licensing@grantsupport.io` (or repository maintainer).
