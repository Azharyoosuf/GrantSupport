# GrantSupport

**Stop sharing admin passwords with support teams — audited, revocable, time-boxed support access through a standard HTTP API.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version: v0.1.0-beta.4](https://img.shields.io/badge/Version-v0.1.0--beta.4-orange.svg)](CHANGELOG.md)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1.0-green.svg)](api/openapi.yaml)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](go.mod)

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
* **NOT a Database / API Proxy**: Does not sit in the data path of your database queries or inspect API payload bodies. GrantSupport sanitises its own audit log. Masking of your own API responses is your application's responsibility.
* **NOT a Messaging Service**: Does not provide notification channels (email, Slack, SMS, or ticketing systems) for delivering bearer tokens. The host application or administrator is responsible for relaying the single-use token through trusted operational channels.
* **NOT a Permissions Engine**: Passes the requested `scope` string into the JWT claims; your host application remains responsible for evaluating and enforcing domain permissions.
* **NOT a Ticketing or Approval Workflow Engine**: Approval or ticketing workflows belong in the host application, which calls `POST /api/v1/auth/support/grant` once a request is approved.

---

## 3. Project Status & Guarantees

* **Status**: Beta / Active Development
* **Current Release**: `v0.1.0-beta.4`
* **License**: MIT License (`MIT`)
* **Deployment**: 100% Self-Hosted (No external accounts or cloud dependencies required)
* **Telemetry**: None (Zero telemetry, zero phone-home, zero heartbeat pings)
* **Databases Supported**: PostgreSQL 16, MySQL 8.0 and 8.4, MariaDB 10.5 and 11.4, SQLite (pure Go)
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
# {"service":"GrantSupport Engine","status":"UP","version":"v0.1.0-beta.4"}

# Deep readiness probe (database and cache connectivity)
curl http://localhost:8080/health/ready
# {"database":"UP","mode":"valkey-enabled","status":"READY","valkey":"UP","version":"v0.1.0-beta.4"}
```

---

## 5. Measured Runtime Characteristics

GrantSupport is designed as a lightweight application-layer service. In the `v0.1.0-beta.3` reference validation environment, the measured resource footprint and performance baseline were as follows:

### 5.1 Resource Footprint (Approximate Reference Figures)
> [!NOTE]
> The binary size, container image size, and memory RSS figures below are **approximate, unmeasured reference observations** from a single development container and are not verified by automated tests. You can measure them on your target machine using:
> - **Static Binary Size**: `CGO_ENABLED=0 go build -ldflags="-w -s" -o grantsupport ./cmd/server && ls -lh grantsupport`
> - **Docker Image Size**: `docker build -t grantsupport . && docker image inspect grantsupport --format='{{.Size}}'`
> - **Container Memory (RSS)**: `docker stats --no-stream`

* **Final Docker Image Size**: ~**12.5 MB** compressed download / ~**39.4 MB** uncompressed content (approximate).
* **Go Static Binary Size**: ~**32.3 MB** stripped with `-ldflags="-w -s"` (approximate; varies by Go version and target architecture).
* **Idle Memory (RSS)**: Approximately **6.08 MiB** (single container, approximate).
* **Under-Load Memory (250 Workers)**: Remained **< 15.0 MiB** RSS (approximate).
* **Idle CPU Usage**: **0.00%**.
* **Startup to Ready**: **< 200 ms**.

### 5.2 Reference Performance Baseline

To reproduce the embedded and live-database benchmarks locally against running PostgreSQL (`5432`), MySQL (`3306`), MariaDB (`3307`), and Valkey (`6379`) containers:
```bash
TEST_POSTGRES_URL="postgresql://grantsupport:secretpassword@127.0.0.1:5432/grantsupport?sslmode=disable" \
TEST_MYSQL_URL="grantsupport:secretpassword@tcp(127.0.0.1:3306)/grantsupport?parseTime=true" \
TEST_MARIADB_URL="grantsupport:secretpassword@tcp(127.0.0.1:3307)/grantsupport?parseTime=true" \
VALKEY_CACHE_URL="valkey://127.0.0.1:6379/0" \
go test -v -run "TestRealDatabaseBenchmarks|TestConcurrencyBenchmarks" ./pkg/grantsupport
```

#### Environment A — Windows 11 (`x86_64`)
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

#### Environment B — macOS Apple Silicon (`ARM64`)
*Measurements gathered in reference validation environment (Apple M5, 24 GB Unified Memory, macOS ARM64 / Docker Linux container) via `TestRealDatabaseBenchmarks` and `TestConcurrencyBenchmarks` (embedded Go engine calling embedded in-memory SQLite vs. real PostgreSQL 16, MySQL 8.4, and MariaDB 11.4 Docker database containers).*

| Operation | Environment (Engine + Backend) | Throughput | p50 Latency | p95 Latency | p99 Latency |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CreateSupportGrant** | Embedded Engine + SQLite (In-Memory) | 13,945.1 req/s | 0.07 ms | 0.08 ms | 0.10 ms |
| **SupportLogin (Redeem)** | Embedded Engine + SQLite (In-Memory) | 1,399.8 req/s | 0.71 ms | 0.74 ms | 0.96 ms |
| **RevokeSupportGrant** | Embedded Engine + SQLite (In-Memory) | 7,339.7 req/s | 0.12 ms | 0.26 ms | 0.26 ms |
| **IsTokenRevoked** | Embedded Engine + SQL In-Memory | 282,418.9 req/s | < 0.01 ms | < 0.01 ms | 0.02 ms |
| **CreateSupportGrant** | Embedded Engine + PostgreSQL 16 (Docker Network) | 243.5 req/s | 3.47 ms | 10.35 ms | 15.17 ms |
| **SupportLogin (Redeem)** | Embedded Engine + PostgreSQL 16 (Docker Network) | 363.2 req/s | 2.11 ms | 5.45 ms | 8.67 ms |
| **CreateSupportGrant** | Embedded Engine + MySQL 8.4 (Docker Network) | 216.7 req/s | 4.31 ms | 6.24 ms | 7.45 ms |
| **SupportLogin (Redeem)** | Embedded Engine + MySQL 8.4 (Docker Network) | 240.9 req/s | 4.31 ms | 5.76 ms | 6.13 ms |
| **CreateSupportGrant** | Embedded Engine + MariaDB 11.4 (Docker Network) | 366.9 req/s | 2.55 ms | 3.30 ms | 8.26 ms |
| **SupportLogin (Redeem)** | Embedded Engine + MariaDB 11.4 (Docker Network) | 451.3 req/s | 2.05 ms | 2.59 ms | 5.78 ms |
| **Concurrency Scaling** | 1 $\rightarrow$ 250 Workers (Embedded Engine + SQLite In-Memory) | 1,338.3 $\rightarrow$ 4,739.8 req/s | — | — | 0 Errors |

> [!NOTE]
> These figures are reference measurements from the specific `v0.1.0-beta.3` validation environment. They are **not** universal performance guarantees or production capacity claims. Real-world performance depends heavily on database engine, network latency, disk I/O, and deployment topology.

---

## 6. Key Security Invariants

* **Cross-Tenant Isolation**: Hard SQL constraints and query scoping ensure Tenant A cannot view, modify, or revoke Tenant B tokens or sessions.
* **Zero Token Persistence**: Single-use raw bearer tokens are returned exactly once upon creation and stored exclusively as SHA-256 hashes in `gs_support_grants`.
* **Fail-Closed Verification**: Unknown key IDs (`kid`), expired grants, and tampering fail closed immediately.
* **Cryptographic Hash Chaining**: Every lifecycle mutation writes an append-only, SHA-256 chained entry into `gs_audit_events`, tamper-evident against edits to individual event records. Someone with database write access could recompute the chain, so external checkpointing of the chain head is planned, not yet implemented.
* **Token Delivery Boundary**: GrantSupport does not provide a messaging channel for transferring the resulting bearer credential. The host organization is responsible for securely relaying the one-time token through its existing trusted operational channel.

---

## 7. API Overview

GrantSupport exposes a clean, secure REST surface. The authoritative OpenAPI 3.1 specification is maintained in [`api/openapi.yaml`](api/openapi.yaml).

### Health & Observability
1. **`GET /health/live`** & **`GET /health/ready`** (Public) — Process liveness and deep dependency readiness probes.
2. **`GET /metrics`** (Public / SRE Network) — Native Prometheus metrics exposition format with bounded cardinality.
3. **`GET /.well-known/jwks.json`** (Public) — RFC 7517 JWKS with public RSA keys and `kid` tracking.

### Direct Delegation & Session Management
4. **`POST /api/v1/auth/support/grant`** (Admin JWT, Rate-limited) — Customer admin creates a direct time-bounded delegation grant.
5. **`POST /api/v1/auth/support/login`** (Public, Rate-limited) — Support agent claims single-use token and receives short-lived RS256 JWT.
6. **`GET /api/v1/auth/support/sessions`** (Admin JWT) — Lists active redeemed support sessions for tenant.
7. **`DELETE /api/v1/auth/support/sessions/{grantId}`** (Admin JWT) — Terminates a specific active support session.
8. **`POST /api/v1/auth/support/logout`** (Support Agent JWT) — Agent voluntary session logout.
9. **`POST /api/v1/auth/support/revoke`** (Admin JWT, Rate-limited) — Tenant-wide revocation of all pending grants and active sessions.

### Cryptographic Audit Ledger
10. **`GET /api/v1/audit/events`** (Admin JWT) — Paginated audit log retrieval.
11. **`POST /api/v1/audit/verify`** (Admin JWT) — Cryptographically verifies unbroken SHA-256 hash chain with optional actor and event_type filtering.

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
		// Optional: wire Valkey/Redis for distributed locks, revocation cache, and rate limiting:
		// grantsupport.WithRedis(redisClient),
		// Optional: configure trusted reverse-proxy CIDRs when mounting engine.HTTPHandler():
		// grantsupport.WithTrustedProxies([]string{"127.0.0.1", "::1", "172.16.0.0/12"}),
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

### Path C: Reverse Proxies & `TRUSTED_PROXIES` (Required Behind nginx, Traefik, Cloudflare, or Docker)

GrantSupport **does not blindly trust** `CF-Connecting-IP`, `X-Real-IP`, or `X-Forwarded-For` headers. `security.ExtractClientIP` only honors forwarded IP headers when the immediate TCP peer (`r.RemoteAddr`) matches an entry in `TRUSTED_PROXIES` (default: `127.0.0.1,::1`) or `grantsupport.WithTrustedProxies(...)`.

> [!IMPORTANT]
> If you deploy GrantSupport behind **nginx**, **Traefik**, **Cloudflare**, an **AWS ALB**, or inside a **Docker bridge network**, the immediate TCP connection comes from the proxy container or load balancer IP (not `127.0.0.1`). You **must** set `TRUSTED_PROXIES` to the IP or CIDR of your reverse proxy. Otherwise:
> 1. **Per-IP rate limiting** will bucket all external users under the reverse proxy's single IP address.
> 2. **Per-grant `whitelisted_ips` enforcement** at `/api/v1/auth/support/login` will compare the grant's whitelist against the proxy's internal IP instead of the support agent's real IP.

Example `docker-compose.yml` running behind an nginx or Traefik reverse proxy on a dedicated Docker subnet:

```yaml
services:
  reverse-proxy:
    image: nginx:1.27-alpine
    ports:
      - "443:443"
    networks:
      grantsupport_net:
        ipv4_address: 172.28.0.10

  grantsupport:
    build: .
    environment:
      PORT: "8080"
      DATABASE_DIALECT: postgres
      DATABASE_URL: postgresql://grantsupport:secretpassword@postgres:5432/grantsupport?sslmode=disable
      # Trust only the reverse-proxy container IP (or subnet CIDR) to supply X-Forwarded-For / X-Real-IP:
      TRUSTED_PROXIES: "127.0.0.1,::1,172.28.0.10/32"
      # Optional Valkey URL (unset/empty by default for SQL-only mode):
      VALKEY_CACHE_URL: "valkey://valkey:6379/0"
    networks:
      grantsupport_net:
        ipv4_address: 172.28.0.20

networks:
  grantsupport_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
```

---

## 9. Security Model

### Default: RS256 JWT Bearer Authentication + Revocation
* Standard HTTP API endpoints use asymmetric RS256 JWTs.
* Active session revocation is verified against the `RevocationStore`.
* If the revocation store fails, requests fail closed with HTTP 503 `REVOCATION_CHECK_UNAVAILABLE`.

### Companion Project: BulletproofAuth
* The Ed25519 per-request HTTP signing and nonce replay protection middleware formerly bundled in GrantSupport now lives in its own standalone repository: [`github.com/azharyoosuf/bulletproofauth`](https://github.com/azharyoosuf/bulletproofauth).

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

GrantSupport is open-source software licensed under the **[MIT License](LICENSE)**.

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
