# GrantSupport

**Stop sharing admin passwords with support teams — audited, revocable, time-boxed support access through a standard HTTP API.**

[![License: AGPL 3.0](https://img.shields.io/badge/License-AGPL_3.0-blue.svg)](LICENSE)
[![Version: v0.1.0-beta.3](https://img.shields.io/badge/Version-v0.1.0--beta.3-orange.svg)](CHANGELOG.md)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1.0-green.svg)](api/openapi.yaml)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](go.mod)

> [!NOTE]
> **Beta software**: GrantSupport is under active development. APIs, implementation details, and configuration may change before the first stable release.

GrantSupport solves the **vendor support access problem** for multi-tenant SaaS platforms. Rather than sharing static administrator credentials, creating permanent support accounts, or leaving un-audited backdoor access in production databases, customer administrators use GrantSupport to issue single-use, time-limited delegation tokens with cryptographic audit logging and immediate session revocation.

---

## 1. Why GrantSupport Exists

Modern SaaS applications frequently need customer service engineers or maintenance agents to investigate tenant-specific issues in production. Common industry workarounds introduce severe security risks:

* **Shared Credentials**: Support teams sharing administrative passwords or root API keys across internal communication channels.
* **Permanent Support Accounts**: "Ghost" admin users provisioned for vendor personnel that remain active indefinitely after maintenance is complete.
* **Unrevocable Access**: Inability for a customer administrator to instantly terminate an active vendor investigation session from their tenant settings.
* **Weak Auditability**: Basic database logs that can be manipulated, truncated, or bypassed without cryptographic detection.

GrantSupport provides an isolated, dedicated engine to govern this lifecycle from delegation to revocation.

---

## 2. What GrantSupport Does NOT Do

To maintain a strict security boundary and operational simplicity, GrantSupport is tightly focused:

* **NOT an IAM / Identity Provider**: Does not handle primary user login, passwords, SAML, LDAP, or social OAuth.
* **NOT a Privileged Access Management (PAM) Platform**: Does not manage bastion hosts, SSH keys, RDP gateways, or Kubernetes cluster credentials.
* **NOT a Database / API Proxy**: Does not sit in the data path of your database queries or inspect API payload bodies.
* **NOT a Messaging Service**: Does not provide notification channels (email, Slack, SMS, or ticketing systems) for delivering bearer tokens. The host application or administrator is responsible for relaying the single-use token through trusted operational channels.
* **NOT a Permissions Engine**: Passes the requested `scope` string into the JWT claims; your host application remains responsible for evaluating and enforcing domain permissions.

---

## 3. Project Status & Guarantees

* **Status**: Beta / Active Development
* **Current Release**: `v0.1.0-beta.3`
* **License**: GNU Affero General Public License v3.0 (`AGPL-3.0-only`)
* **Deployment**: 100% Self-Hosted (No external accounts or cloud dependencies required)
* **Telemetry**: None (Zero telemetry, zero phone-home, zero heartbeat pings)
* **Databases Supported**: PostgreSQL 16+, MySQL 8.0+, MariaDB 10.5+, SQLite 3
* **Cache Backends Supported**: Valkey 7.2+, Redis 7+, or In-Process SQL Fallback (No Cache Mode)
* **Primary Integration**: Language-agnostic HTTP REST API
* **Secondary Integration**: Embedded Go engine (`pkg/grantsupport`)
* **Operational Runbooks**:
  * [Developer Integration Guide](docs/INTEGRATION_GUIDE.md)
  * [Prometheus Observability & Metrics](docs/OBSERVABILITY.md)
  * [Zero-Downtime Key Rotation Runbook](docs/KEY_ROTATION.md)
  * [Security Model & Threat Matrix](docs/SECURITY_MODEL.md)

---

## 4. Quick Start (Standalone Server via Docker)

### 4.1 Clone and Start Services
```bash
git clone https://github.com/azharyoosuf/grantsupport.git
cd grantsupport
docker compose up -d
```

### 4.2 Verify Health & Readiness
```bash
# Liveness probe (process running)
curl http://localhost:8080/health/live
# {"service":"GrantSupport Engine","status":"UP","version":"v0.1.0-beta.3"}

# Deep readiness probe (database and cache connectivity)
curl http://localhost:8080/health/ready
# {"database":"UP","mode":"valkey-enabled","status":"READY","valkey":"UP","version":"v0.1.0-beta.3"}
```

---

## 5. Measured Runtime Characteristics

GrantSupport is designed as a lightweight application-layer service. In the `v0.1.0-beta.3` reference validation environment, the measured resource footprint and performance baseline were as follows:

### 5.1 Resource Footprint
* **Final Docker Image Size**: **12.5 MB** compressed download / **39.4 MB** uncompressed content.
* **Go Static Binary Size**: **32.3 MB** (stripped with `-ldflags="-w -s"`).
* **Idle Memory (RSS)**: Approximately **6.08 MiB** (single container).
* **Under-Load Memory (250 Workers)**: Remained **< 15.0 MiB** RSS.
* **Idle CPU Usage**: **0.00%**.
* **Startup to Ready**: **< 200 ms**.

### 5.2 Reference Performance Baseline
*Measurements gathered in reference validation environment (12th Gen Intel Core i5-12450H, 16 GB RAM, Windows 11 / Docker Linux container).*

| Operation | Environment | Throughput | p50 Latency | p95 Latency | p99 Latency |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CreateSupportGrant** | SQLite (In-Memory) | 4,831.2 req/s | < 1.0 ms | 1.11 ms | 1.62 ms |
| **SupportLogin (Redeem)** | SQLite (In-Memory) | 964.2 req/s | 1.01 ms | 2.08 ms | 2.66 ms |
| **RevokeSupportGrant** | SQLite (In-Memory) | 5,057.4 req/s | < 1.0 ms | 0.99 ms | 0.99 ms |
| **IsTokenRevoked** | SQL In-Memory | > 40,000 req/s | < 0.1 ms | < 0.1 ms | < 0.1 ms |
| **CreateSupportGrant** | MySQL 8.4 (Network) | 29.9 req/s | 32.97 ms | 43.46 ms | — |
| **SupportLogin (Redeem)** | MySQL 8.4 (Network) | 38.7 req/s | 25.02 ms | 35.29 ms | — |
| **Concurrency Scaling** | 1 $\rightarrow$ 250 Workers | 296.6 $\rightarrow$ 922.2 req/s | — | — | 0 Errors |

> [!NOTE]
> These figures are reference measurements from the specific `v0.1.0-beta.3` validation environment. They are **not** universal performance guarantees or production capacity claims. Real-world performance depends heavily on database engine, network latency, disk I/O, and deployment topology.

---

## 6. Key Security Invariants

* **Cross-Tenant Isolation**: Hard SQL constraints and query scoping ensure Tenant A cannot view, approve, modify, or revoke Tenant B tokens or access requests.
* **Self-Approval Prohibition**: Support agents are mathematically prevented from approving their own access requests (`SELF_APPROVAL_FORBIDDEN`).
* **Zero Token Persistence**: Single-use raw bearer tokens are returned exactly once upon creation/approval and stored exclusively as SHA-256 hashes in `gs_support_grants`.
* **Fail-Closed Verification**: Unknown key IDs (`kid`), expired grants, and tampering fail closed immediately.
* **Cryptographic Hash Chaining**: Every lifecycle mutation writes an append-only, SHA-256 chained entry into `gs_audit_events`.
* **Token Delivery Boundary**: Approval controls whether access may be granted. GrantSupport does not provide a messaging channel for transferring the resulting bearer credential. The host organization is responsible for securely relaying the one-time token through its existing trusted operational channel.

---

## 7. API Overview

GrantSupport exposes a clean, secure REST surface. The authoritative OpenAPI 3.1 specification is maintained in [`api/openapi.yaml`](api/openapi.yaml).

### Health & Observability
1. **`GET /health/live`** & **`GET /health/ready`** (Public) — Process liveness and deep dependency readiness probes.
2. **`GET /metrics`** (Public / SRE Network) — Native Prometheus metrics exposition format with bounded cardinality.
3. **`GET /.well-known/jwks.json`** (Public) — RFC 7517 JWKS with public RSA keys and `kid` tracking.

### Just-In-Time Access Request & Approval Workflow
4. **`POST /api/v1/access-requests`** (Support Agent JWT, Rate-limited) — Submit JIT access request with reason, duration, and scope.
5. **`GET /api/v1/access-requests`** (Admin or Agent JWT) — Query paginated access requests for the tenant.
6. **`GET /api/v1/access-requests/{id}`** (Admin or Agent JWT) — Retrieve specific access request details.
7. **`POST /api/v1/access-requests/{id}/approve`** (Admin JWT, Rate-limited) — Customer admin approves request, generating single-use grant token.
8. **`POST /api/v1/access-requests/{id}/reject`** (Admin JWT, Rate-limited) — Customer admin rejects request with reason.
9. **`POST /api/v1/access-requests/{id}/cancel`** (Admin or Agent JWT) — Cancels a pending access request.

### Direct Delegation & Session Management
10. **`POST /api/v1/auth/support/grant`** (Admin JWT, Rate-limited) — Customer admin creates a direct time-bounded delegation grant.
11. **`POST /api/v1/auth/support/login`** (Public, Rate-limited) — Support agent claims single-use token and receives short-lived RS256 JWT.
12. **`GET /api/v1/auth/support/sessions`** (Admin JWT) — Lists active redeemed support sessions for tenant.
13. **`DELETE /api/v1/auth/support/sessions/{grantId}`** (Admin JWT) — Terminates a specific active support session.
14. **`POST /api/v1/auth/support/logout`** (Support Agent JWT) — Agent voluntary session logout.
15. **`POST /api/v1/auth/support/revoke`** (Admin JWT, Rate-limited) — Tenant-wide revocation of all pending grants and active sessions.

### Cryptographic Audit Ledger
16. **`GET /api/v1/audit/events`** (Admin JWT) — Paginated audit log retrieval.
17. **`POST /api/v1/audit/verify`** (Admin JWT) — Cryptographically verifies unbroken SHA-256 hash chain with optional actor and event_type filtering.

---

## 8. Integration Paths

### Path A: Standalone HTTP Service (Primary — Language-Agnostic)
Run `cmd/server` as an independent container or binary. Any application written in **Node.js, Python, Java, Go, C#, Ruby, PHP, or Rust** communicates with GrantSupport via standard HTTP JSON requests. The HTTP API is framework-independent.

### Path B: Embedded Go Engine (Secondary — Go In-Process)
For applications written in Go that prefer zero network overhead, embed the engine directly into the application process:

```go
package main

import (
	"context"
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
	"grantsupport/pkg/grantsupport"
)

func main() {
	db, _ := sql.Open("sqlite", "file:app.db?cache=shared&_pragma=foreign_keys(1)")

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		log.Fatalf("Failed to initialize GrantSupport: %v", err)
	}
	defer engine.Close()

	// Direct Go API calls:
	// rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "BILLING_ONLY", []string{"198.51.100.4"})
	// instID, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID, "198.51.100.4")
	// err = engine.RevokeSupportGrant(ctx, instID, adminID)
	// valid, err := engine.VerifyAuditChain(ctx, instID)
}
```

---

## 9. Security Model

### Default: RS256 JWT Bearer Authentication + Revocation
* Standard HTTP API endpoints use asymmetric RS256 JWTs.
* Active session revocation is verified against the `RevocationStore`.
* If the revocation store fails, requests fail closed with HTTP 503 `REVOCATION_CHECK_UNAVAILABLE`.

### Optional: BulletproofAuth (For Go Embedders)
* `engine.BulletproofMiddleware(keyStore)` provides an opt-in 5-layer Ed25519 request-signing verification layer for custom machine-to-machine Go routes.
* **Note**: BulletproofAuth is an opt-in middleware for embedded Go applications and is **not** automatically applied to default public HTTP endpoints.

For full technical specifications, see [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

---

## 10. Known Limitations & Operational Considerations

1. **No CORS Middleware by Design**: GrantSupport does not attach permissive CORS headers. Web browsers should not call GrantSupport directly; calls should be proxied through your host application's backend.
2. **Fail-Closed Valkey Availability**: If Valkey is configured and becomes unreachable during active operation, rate limiting and revocation checks **fail closed** with HTTP 503 to prevent security bypasses.
3. **Scope Non-Enforcement**: GrantSupport passes the `scope` string through to the JWT claims. **GrantSupport does not enforce your application's domain permissions.** Your application must inspect the JWT `scope` claim to restrict access.
4. **Host Application Authorization**: The host application remains responsible for verifying administrator permissions before calling `/grant` or `/revoke`.
5. **Agent Identity Verification**: The host application is responsible for verifying the physical identity of the engineer before assigning them an `agentId` UUID.
6. **Network & DDoS Protection**: Broad volumetric DDoS and WAF protections must be provided by upstream reverse proxies (e.g. Cloudflare, AWS ALB, NGINX).

---

## 11. License

GrantSupport is licensed under the **[GNU Affero General Public License version 3.0 (AGPL-3.0-only)](LICENSE)**.

---

## 12. Contributing, Support & Security

* **Contributing Guidelines**: See [`CONTRIBUTING.md`](CONTRIBUTING.md).
* **Support & Help**: See [`SUPPORT.md`](SUPPORT.md).
* **Community Code of Conduct**: See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
* **Vulnerability Reporting**: See [`SECURITY.md`](SECURITY.md).
* **Technical Architecture**: See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
* **Security Model**: See [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).
* **Integration Guide**: See [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md).
* **Roadmap & Future Extensions**: See [`docs/FUTURE.md`](docs/FUTURE.md).
