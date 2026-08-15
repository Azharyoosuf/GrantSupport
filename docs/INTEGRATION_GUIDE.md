# GrantSupport Developer Integration Guide

This guide details how to integrate GrantSupport into your multi-tenant SaaS platform, covering both the **Language-Agnostic HTTP REST API** (primary) and the **Embedded Go Engine** (secondary).

---

## 1. Integration Architecture & Network Model

GrantSupport is an internal infrastructure service designed for backend-to-backend communication:

```
[Browser / Admin Dashboard]
            │
            ▼ (Session Cookie / OAuth)
[Host Application Backend (Proxy / BFF)]
            │
            ▼ (Internal VPC / Service-to-Service HTTP)
[GrantSupport API (:8080)]
```

> **CORS Notice**: GrantSupport does not attach Cross-Origin Resource Sharing (`Access-Control-Allow-Origin`) headers. Your host application's backend should handle administrative requests and forward calls to GrantSupport internally.

---

## 2. HTTP REST API Integration (Primary)

The HTTP API is language-agnostic. All request payloads must be `application/json` and error responses follow the **RFC 9457 Problem Details** standard (`application/problem+json`).

### Step 1: Create a Delegated Support Grant (Customer Administrator)
When a customer administrator clicks "Grant Support Access" in your settings dashboard, your backend issues a request to GrantSupport:

```bash
curl -X POST http://localhost:8080/api/v1/auth/support/grant \
  -H "Authorization: Bearer <ADMIN_JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "durationMinutes": 60,
    "scope": "BILLING_READ_ONLY",
    "whitelistedIps": ["198.51.100.4", "203.0.113.0/24"]
  }'
```

#### Request Fields (`GrantSupportInput`):
* `durationMinutes` (*required, int*): Grant lifetime in minutes (1 to 1440).
* `scope` (*optional, string*): Permission label passed to the JWT (default: `FULL_ACCESS`).
* `whitelistedIps` (*optional, []string*): Array of authorized IPv4/IPv6 addresses or CIDR subnets.

#### Response (`201 Created`):
```json
{
  "success": true,
  "message": "Support access token generated successfully.",
  "token": "550e8400-e29b-41d4-a716-446655440000_9f83a8b9487c6e12e2057639f28d8442..."
}
```

---

### Step 2: Support Agent Login (Claim Single-Use Token)
The support agent enters the token into the support portal. The support portal backend calls GrantSupport to claim the token:

```bash
curl -X POST http://localhost:8080/api/v1/auth/support/login \
  -H "Content-Type: application/json" \
  -d '{
    "token": "550e8400-e29b-41d4-a716-446655440000_9f83a8b9487c6e12e2057639f28d8442...",
    "agentId": "7f4c935b-16d7-4f9e-a8f2-39c4a852b719"
  }'
```

#### Request Fields (`SupportLoginInput`):
* `token` (*required, string*): The raw support token string.
* `agentId` (*required, string UUID*): The explicit UUID of the support engineer claiming the session.

#### Response (`200 OK`):
```json
{
  "success": true,
  "message": "Support agent authenticated successfully.",
  "institution_id": "550e8400-e29b-41d4-a716-446655440000",
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

> **Security Note on Single-Use**: Attempting to reuse the same token a second time immediately returns HTTP 401 Problem Details (`SUPPORT_LOGIN_FAILED`).

---

### Step 3: Using the Support Agent JWT in Your Application
The support agent attaches the `access_token` as a Bearer token in requests to your application:

```bash
curl -X GET https://api.yourcompany.com/v1/invoices \
  -H "Authorization: Bearer <SUPPORT_AGENT_JWT>"
```

#### Important: Scope Enforcement Responsibility
GrantSupport places the `scope` (e.g. `BILLING_READ_ONLY`) and `role: SUPPORT_AGENT` in the JWT payload. **GrantSupport does not enforce your application's database permissions.** Your application must verify:
1. Verify the JWT signature using GrantSupport's public key (`JWT_PUBLIC_KEY`).
2. Inspect the `role` and `scope` claims to restrict actions (e.g. read-only vs write).

---

### Step 4: Voluntary Support Agent Logout
When the support agent finishes their task, they voluntarily terminate their session:

```bash
curl -X POST http://localhost:8080/api/v1/auth/support/logout \
  -H "Authorization: Bearer <SUPPORT_AGENT_JWT>"
```

#### Response (`200 OK`):
```json
{
  "success": true,
  "message": "Support agent session logged out successfully."
}
```

---

### Step 5: Optional In-Band JIT Access Request & Approval Workflow

GrantSupport allows support agents to initiate access requests that customer administrators review and approve in-band.

#### 1. Agent Submits Access Request (`POST /api/v1/access-requests`):
```bash
curl -X POST http://localhost:8080/api/v1/access-requests \
  -H "Authorization: Bearer <AGENT_JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "targetService": "billing-service",
    "reason": "Investigating ticket #8492 - customer payment discrepancy",
    "durationMinutes": 60,
    "scope": "billing:read",
    "whitelistedIps": ["198.51.100.4"]
  }'
```

#### 2. Customer Admin Approves Access Request (`POST /api/v1/access-requests/{id}/approve`):
```bash
curl -X POST http://localhost:8080/api/v1/access-requests/01a004a0-7b2c-7b28-9e5d-e88103bc9505/approve \
  -H "Authorization: Bearer <ADMIN_JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "durationMinutes": 45,
    "scope": "billing:read"
  }'
```

#### Response (`200 OK`):
```json
{
  "success": true,
  "requestId": "01a004a0-7b2c-7b28-9e5d-e88103bc9505",
  "status": "APPROVED",
  "grantId": "01a004a1-17c3-7b32-97fc-fa9214d394c0",
  "rawToken": "550e8400-e29b-41d4-a716-446655440000_f92b4c10e82a4d70923f1b0a...",
  "expiresAt": "2026-08-15T15:30:00Z"
}
```

> [!IMPORTANT]
> **Token Delivery Boundary & Operational Limitation**:
> "Approval controls whether access may be granted. GrantSupport does not provide a messaging channel for transferring the resulting bearer credential. The host organization is responsible for securely relaying the one-time token through its existing trusted operational channel."

---

### Step 6: Customer Admin Immediate Revocation
If a customer administrator wants to immediately revoke all active vendor access for their tenant:

```bash
curl -X POST http://localhost:8080/api/v1/auth/support/revoke \
  -H "Authorization: Bearer <ADMIN_JWT>"
```

#### Response (`200 OK`):
```json
{
  "success": true,
  "message": "All support delegations revoked successfully."
}
```
*Result: All pending unredeemed tokens for this tenant are expired, and all active support agent JWT sessions are invalidated in the revocation store.*

---

## 3. Go In-Process Embedding (Secondary)

If your host application is written in Go, you can embed GrantSupport directly:

```go
package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"grantsupport/pkg/grantsupport"
)

func main() {
	ctx := context.Background()

	// 1. Initialize with caller-managed database pool
	db, err := sql.Open("sqlite", "file:app.db?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		log.Fatalf("Failed to initialize engine: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// 2. Create support grant in Go
	token, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "READ_ONLY", []string{"198.51.100.4"})
	if err != nil {
		log.Fatalf("Create grant failed: %v", err)
	}

	// 3. Redeem grant in Go
	tenantID, jwtToken, err := engine.SupportLogin(ctx, token, agentID, "198.51.100.4")
	if err != nil {
		log.Fatalf("Support login failed: %v", err)
	}
	log.Printf("Issued JWT for tenant %s: %s", tenantID, jwtToken[:30])

	// 4. Verify audit ledger integrity
	valid, err := engine.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		log.Fatalf("Audit chain verification failed: %v", err)
	}

	// 5. Admin revoke
	if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		log.Fatalf("Revoke failed: %v", err)
	}
}
```

---

## 4. Standardized Scope Policy & Matching (`pkg/scope`)

GrantSupport carries the `scope` string through the RS256 JWT claim. Application-level domain authorization is enforced by your host application. To simplify hierarchical permission evaluation, GrantSupport provides the pure-Go `pkg/scope` utility:

```go
import "grantsupport/pkg/scope"

// 1. Wildcard subtree matching
scope.Matches("billing:*", "billing:read")            // true
scope.Matches("billing:*", "billing:read:export:csv") // true

// 2. Exact matching
scope.Matches("billing:read", "billing:read")         // true
scope.Matches("billing:read", "billing:write")        // false

// 3. Multi-scope string parsing (comma or space separated)
scope.Matches("billing:read, org:admin", "org:admin") // true

// 4. Global wildcard
scope.Matches("*", "any:arbitrary:scope")             // true
```

---

## 5. Webhooks & Event Durability Boundaries

GrantSupport emits signed HMAC-SHA256 webhooks for grant and session lifecycle transitions:
* `grant.created`
* `grant.claimed`
* `grant.revoked`
* `session.terminated`

### Durability & Retry Boundary
* **In-Memory Bounded Queue**: Retries are buffered in-memory up to a capacity limit of **5,000 events**.
* **Retry Schedule**: Bounded at **3 delivery attempts** with exponential backoff (1s, 5s, 15s).
* **Crash Semantics**: Pending in-memory retries are **ephemeral** and will be lost if the server process crashes. For mission-critical external auditing, poll the append-only `GET /api/v1/audit/events` REST API.
* **Dead-Letter Handling**: Events that exhaust 3 delivery attempts emit `WARN [WEBHOOK_DEAD_LETTER]` and are safely dropped to prevent memory leaks.

