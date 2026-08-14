# Developer Integration Guide

This guide walks developers step-by-step through integrating **GrantSupport** into an existing or new web application.

---

## 1. Prerequisites

Before integrating GrantSupport, ensure your environment provides:
* **Go 1.22+** (for Go native SDK / microservice deployment)
* **PostgreSQL 14+** (for local data plane storage)
* **Valkey 7.2+ or Redis 7+** (for distributed locking & token version caching)

---

## 2. Step 1 — Database Migration Setup

Run the GrantSupport database migration script to set up `SupportGrant`, `AuditEvent`, and append-only immutability triggers:

```bash
psql -h localhost -U postgres -d your_app_db -f migrations/000001_create_grantsupport_tables.sql
psql -h localhost -U postgres -d your_app_db -f migrations/000002_add_immutability_triggers.sql
```

---

## 3. Step 2 — Configuration Setup

Create an `.env` file or export environment variables for GrantSupport:

```env
# Server Configuration
PORT=8085
NODE_ENV=production

# Database & Cache (Data Plane)
DATABASE_DIALECT=postgres
DATABASE_URL=postgres://postgres:password@localhost:5432/your_app_db?sslmode=disable
VALKEY_CACHE_URL=valkey://localhost:6379/0

# JWT Signing Keys (RSA-2048)
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..."
```

---

## 4. Step 3 — Adding GrantSupport Endpoints to Your Router

In your Go Chi web router, mount the GrantSupport controller handlers:

```go
package main

import (
	"net/http"
	"github.com/go-chi/chi/v5"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/middleware"
)

func RegisterSupportRoutes(r chi.Router, deps *Dependencies) {
	// Public Support Agent Login Endpoint (Agents redeem token for JWT)
	r.Post("/api/v1/auth/support/login", controller.CatchAsync(deps.SupportController.SupportLogin))

	// Authenticated Support Agent Logout Endpoint
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireRoles("SUPPORT_AGENT"))
		r.Post("/api/v1/auth/support/logout", controller.CatchAsync(deps.SupportController.SupportLogout))
	})

	// Customer-Admin Role-Gated Delegation Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireRoles("ADMINISTRATOR", "OWNER", "ADMIN"))
		
		// Customer Admin issues new support grant token
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(deps.SupportController.GrantSupport))
		
		// Customer Admin revokes all active support tokens and active sessions
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(deps.SupportController.RevokeSupport))
	})
}
```

---

## 5. Step 4 — Embedding the Customer Grant UI Widget

Include the lightweight GrantSupport frontend widget in your web application's settings dashboard:

```html
<!-- Settings -> Support Access Panel -->
<div id="grantsupport-widget" class="card shadow-sm p-4">
  <h3>Delegated Support Access</h3>
  <p class="text-muted">Grant temporary, audited access to customer support engineers or AI diagnostics.</p>
  
  <div class="d-flex gap-3 align-items-center mt-3">
    <select id="grant-duration" class="form-select w-auto">
      <option value="15">15 Minutes</option>
      <option value="60" selected>1 Hour</option>
      <option value="240">4 Hours</option>
    </select>
    
    <button id="btn-grant-access" class="btn btn-primary" onclick="generateSupportGrant()">
      Grant Support Access
    </button>
    <button id="btn-revoke-access" class="btn btn-danger" onclick="revokeSupportAccess()">
      Revoke All Access
    </button>
  </div>
  
  <div id="grant-output" class="alert alert-info mt-3 d-none">
    <strong>Support Token:</strong> <code id="token-text"></code>
    <br><small>Provide this token to your support engineer or diagnostic bot.</small>
  </div>
</div>

<script>
async function generateSupportGrant() {
  const duration = parseInt(document.getElementById('grant-duration').value);
  const response = await fetch('/api/v1/auth/support/grant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ duration_minutes: duration })
  });
  const data = await response.json();
  if (data.success) {
    document.getElementById('token-text').innerText = data.grant_token;
    document.getElementById('grant-output').classList.remove('d-none');
  }
}
</script>
```

---

## 6. Step 5 — Verification & Testing

Verify that your integration works properly by running:

```bash
# Test 1: Verify license signature check
go test ./pkg/license/... -v

# Test 2: Verify support login token consumption
go test ./pkg/service/... -run TestSupportLogin -v

# Test 3: Run full parity check
python scripts/parity_audit.py
```
