# GrantSupport — Ephemeral Support Delegation & Audit Engine

> **The Enterprise-Grade Delegated Authorization & Audit Engine for Modern B2B Applications.**
> GrantSupport enables SaaS vendors and self-hosted application developers to receive customer-authorized, time-bound, and fully audited support access without storing passwords, maintaining permanent admin backdoors, or taking on customer PII data liability.

---

## 🌟 Key Architecture & Product Highlights

* **Zero Data-Hosting Liability (Hybrid Control/Data-Plane)**: Customers maintain 100% control over their database, user PII, and infrastructure. GrantSupport runs within their VPC/container while verifying cryptographic license signatures against your JWKS endpoint.
* **Customer-Initiated Delegation**: Support access is never vendor-forced. End-user administrators grant explicit, time-boxed authorization window tokens (e.g. 15m, 1h, 4h).
* **Instant Revocation**: End-users can revoke any active support delegation with a single click.
* **Cryptographic Tamper-Evident Audit Ledger**: Every grant creation, login attempt, and session revocation is recorded in an append-only, SHA-256 hash-chained log protected by database triggers.
* **Cryptographic License & Seat Enforcement**: Enforce seat caps (3, 10, 25, Enterprise) for both Human Support Engineers and Autonomous AI Remediation Agents using Ed25519 asymmetric signatures.

---

## 🏗 System Architecture Overview

```
       ┌─────────────────────────────────────────────────────────────┐
       │             YOUR SAAS HUB (Licensing & JWKS)                 │
       │  - Ed25519 Asymmetric Signatures for License Tokens & APIs  │
       │  - RS256 Keypair for User / Support-Agent Session JWTs      │
       │  - Serves Public Keys via /.well-known/jwks.json             │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
                    Cryptographic License Signature
                                      │
                                      ▼
       ┌─────────────────────────────────────────────────────────────┐
       │            CUSTOMER INFRASTRUCTURE (Docker / VPC)            │
       │                                                             │
       │  ┌──────────────────────┐     ┌──────────────────────────┐  │
       │  │ GrantSupport Core    │ ──► │ Local Database & Valkey   │  │
       │  │ (Go Binary / Container)│     │ (Customer Owned PII/Data)│  │
       │  └──────────────────────┘     └──────────────────────────┘  │
       │                                                             │
       │  1. Verifies License Signature with your Public Key         │
       │  2. Enforces Seat Caps (Human & AI Agents) locally           │
       │  3. Issues Ephemeral Support Tokens & Append-Only Audits     │
       └─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Customer Deployment)

### 1. Docker Compose Setup

Customers deploy GrantSupport alongside their existing PostgreSQL and Valkey/Redis infrastructure using `docker-compose.yml`:

```yaml
version: '3.8'

services:
  grantsupport-core:
    image: your-registry.com/grantsupport-core:v1.0.0
    container_name: grantsupport-core
    ports:
      - "8085:8085"
    environment:
      - PORT=8085
      - DATABASE_URL=postgres://postgres:password@postgres:5432/customer_db?sslmode=disable
      - VALKEY_URL=redis://valkey:6379/0
      - LICENSE_KEY=eyJh... (Signed Ed25519 License Key)
      - JWKS_URL=https://licensing.yourcompany.com/.well-known/jwks.json
    depends_on:
      - postgres
      - valkey

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: customer_db
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"

  valkey:
    image: valkey/valkey:7.2-alpine
    ports:
      - "6379:6379"
```

---

## 🔌 Core API Endpoints

### 1. Issue Delegation Grant (Customer Admin Initiated)
`POST /api/v1/auth/support/grant`
```json
// Headers: Authorization: Bearer <Customer_Admin_JWT>
{
  "duration_minutes": 60,
  "reason": "Investigating invoice discrepancy ticket #4029"
}
```
**Response**:
```json
{
  "success": true,
  "grant_token": "inst_99812_a8b9f10c...",
  "expires_at": "2026-07-30T19:30:00Z"
}
```

### 2. Support Agent Login (Human or AI Agent)
`POST /api/v1/auth/support/login`
```json
{
  "token": "inst_99812_a8b9f10c...",
  "agent_id": "agent_sarah_123"
}
```
**Response**:
```json
{
  "success": true,
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "role": "SUPPORT_AGENT",
  "expires_in": 14400
}
```

### 3. Revoke Delegation Grant (Customer Admin Initiated)
`POST /api/v1/auth/support/revoke`
```json
{
  "success": true,
  "message": "All active support delegation grants revoked immediately."
}
```

---

## 💎 Tier & License Enforcement

GrantSupport enforces tier limits locally inside the customer container without querying your database:

| Feature / Tier | Starter (3 Seats) | Professional (10 Seats) | Business (25 Seats) | Enterprise |
| :--- | :---: | :---: | :---: | :---: |
| **Max Human Agents** | 3 | 10 | 25 | Unlimited |
| **Max AI Remediation Bots** | 1 | 5 | 15 | Custom |
| **Tamper-Evident Ledger** | Yes | Yes | Yes | Yes + S3 Cold Export |
| **Offline Grace Period** | 7 Days | 7 Days | 14 Days | 30 Days / Air-Gapped |

---

## 📄 License & Documentation Index

* 📘 [Architecture Specification](docs/ARCHITECTURE.md) — Deep dive into Control/Data Plane separation and cryptographic design.
* 📗 [Integration Guide](docs/INTEGRATION_GUIDE.md) — Step-by-step developer onboarding and SDK integration guide.
* 📙 [Commercial & Tiering Models](docs/COMMERCIAL_MODELS.md) — Pricing structures, license key generation, and anti-piracy mechanisms.
