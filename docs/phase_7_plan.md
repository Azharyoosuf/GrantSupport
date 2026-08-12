# Phase 7 Implementation Plan: Developer SDK & Client UI Component

## 📌 Problem & Context
1. **Manual Router Registration**: Developers must manually hook controllers into Chi routers.
2. **Missing Frontend Widget**: Clients must build custom HTML/JS UI elements.
3. **SDK drops authentication entirely** (F-7-A — most severe): The original SDK `MountRoutes()` had no middleware on the grant/revoke group, making those endpoints unauthenticated.
4. **Rate limiter never mounted in SDK path** (F-3-C): SDK must also apply `RateLimitMiddleware` to the login endpoint.
5. **Widget DOM ID collisions** (F-7-B / finding #25): Hardcoded IDs break multiple instances.
6. **Widget doesn't check `res.ok`** (F-7-C / finding #26): Non-JSON error responses crash the widget silently.
7. **Widget sends wrong JSON key for duration** (F-1-A): Widget must send `durationMinutes` (camelCase), not `duration_minutes`.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `pkg/sdk/sdk.go` — Authenticated SDK with Rate Limiting

#### [NEW] [sdk.go](file:///d:/Hostel_management/GrantSupport/pkg/sdk/sdk.go)

> **Fix (F-7-A)**: `GrantSupportEngine` accepts `*cache.ValkeyClient` and applies `middleware.NewAuthMiddleware` inside the group — exactly matching `main.go`'s existing wiring.
> **Fix (F-3-C)**: `RateLimitMiddleware` is applied to the login endpoint via `r.With(...).Post(...)`, consistent with the Phase 4 `main.go` diff.

**BEFORE (original draft):**
```go
func (e *GrantSupportEngine) MountRoutes(r chi.Router) {
	r.Post("/api/v1/auth/support/login", controller.CatchAsync(e.Controller.SupportLogin))
	r.Group(func(r chi.Router) {
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(e.Controller.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(e.Controller.RevokeSupport))
	})
}
```

**AFTER:**
```go
package sdk

import (
	"github.com/go-chi/chi/v5"
	"grantsupport/pkg/cache"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/middleware"
)

// GrantSupportEngine is the SDK entry point for integrating GrantSupport
// into any Chi-based application.
type GrantSupportEngine struct {
	Controller  *controller.SupportGrantController
	// ValkeyClient is required for:
	// 1. AuthMiddleware — revocation checks (nil disables revocation; NOT safe for production).
	// 2. RateLimitMiddleware — brute-force protection on the login endpoint.
	ValkeyClient *cache.ValkeyClient
}

// MountRoutes registers all GrantSupport endpoints on the provided router.
// It applies:
// - RateLimitMiddleware (10 req/60s per IP) on the public login endpoint.
// - NewAuthMiddleware on the authenticated grant/revoke/webhook group.
//
// This matches the wiring in cmd/server/main.go exactly (F-7-A fix).
//
// I-6 fix: RegisterWebhook is now included in the authenticated group.
// Method name confirmed from phase_6_plan.md Component 4b: func (c *SupportGrantController) RegisterWebhook(...)
func (e *GrantSupportEngine) MountRoutes(r chi.Router) {
	// Public login endpoint — rate-limited (F-3-C fix for SDK path).
	r.With(
		middleware.RateLimitMiddleware(e.ValkeyClient, 10, 60),
	).Post("/api/v1/auth/support/login", controller.CatchAsync(e.Controller.SupportLogin))

	// Authenticated group — requires valid JWT (F-7-A fix: auth middleware applied here).
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(e.ValkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(e.Controller.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(e.Controller.RevokeSupport))
		// Webhook registration — I-6 fix: missing from original SDK, now added to match main.go routing.
		// Method name: RegisterWebhook (confirmed in phase_6_plan.md Component 4b).
		r.Post("/api/v1/auth/support/webhook", controller.CatchAsync(e.Controller.RegisterWebhook))
	})
}
```

> **Cross-phase call-site audit for `RegisterWebhook` method name (mandatory per process rule)**:
> - Searched phase_6_plan.md Component 4b: method is `func (c *SupportGrantController) RegisterWebhook(...)` — ✔
> - phase_7_plan.md (this file): `e.Controller.RegisterWebhook` — matches exactly ✔
> - No other phase file references this method name directly — ✔
> - **Call sites checked: phase_6, phase_7. All updated: yes.**


---

### Component 2: `web/widget/grantsupport.js` — Fixed Widget

#### [NEW] [grantsupport.js](file:///d:/Hostel_management/GrantSupport/web/widget/grantsupport.js)

> **Fix (F-7-B / finding #25)**: All element lookups use `this.container.querySelector(...)` with unique per-instance ID suffix, not `document.getElementById`. Multiple widget instances on the same page work correctly.
> **Fix (F-7-C / finding #26)**: `res.ok` is checked before calling `res.json()`. `res.json()` is wrapped in try/catch to handle non-JSON error bodies.
> **Fix (F-1-A)**: Widget sends `durationMinutes` (camelCase) to match the live server DTO tag.

**BEFORE (original draft):**
```javascript
// Used hardcoded getElementById('gs-duration'), no res.ok check,
// and sent duration_minutes (snake_case) — all three are bugs.
```

**AFTER:**
```javascript
/**
 * GrantSupportWidget
 * Drop-in UI component for managing delegated support access.
 * Multiple instances on the same page are fully supported.
 *
 * Usage:
 *   <script src="/path/to/grantsupport.js"></script>
 *   <div id="my-support-panel"></div>
 *   <script>
 *     new GrantSupportWidget('my-support-panel', { apiBase: '/api/v1/auth/support' });
 *   </script>
 */
class GrantSupportWidget {
  constructor(containerId, options = {}) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error('[GrantSupportWidget] Container not found:', containerId);
      return;
    }
    this.apiBase = options.apiBase || '/api/v1/auth/support';
    // Unique per-instance suffix prevents DOM ID collisions when multiple widgets
    // are rendered on the same page (F-7-B fix).
    this.uid = containerId + '_' + Math.random().toString(36).slice(2, 8);
    this.init();
  }

  init() {
    this.container.innerHTML = `
      <div style="border:1px solid #e2e8f0; border-radius:8px; padding:16px; font-family:sans-serif;">
        <h4 style="margin-top:0;">Delegated Support Access</h4>
        <p style="color:#64748b; font-size:14px;">Grant temporary, audited access to customer support engineers.</p>
        <div style="display:flex; gap:8px; align-items:center;">
          <select id="${this.uid}_duration" style="padding:8px; border-radius:4px; border:1px solid #cbd5e1;">
            <option value="15">15 Minutes</option>
            <option value="60" selected>1 Hour</option>
            <option value="240">4 Hours</option>
          </select>
          <button id="${this.uid}_btn_grant" style="background:#2563eb; color:#fff; border:none; padding:8px 16px; border-radius:4px; cursor:pointer;">Grant Access</button>
          <button id="${this.uid}_btn_revoke" style="background:#dc2626; color:#fff; border:none; padding:8px 16px; border-radius:4px; cursor:pointer;">Revoke All</button>
        </div>
        <div id="${this.uid}_output" style="display:none; margin-top:12px; padding:8px; background:#f1f5f9; border-radius:4px;">
          <strong>Support Token:</strong> <code id="${this.uid}_token"></code>
        </div>
        <div id="${this.uid}_error" style="display:none; margin-top:8px; color:#dc2626; font-size:13px;"></div>
      </div>
    `;

    // Scope lookups to this.container to avoid ID collisions (F-7-B fix).
    this.container.querySelector(`#${this.uid}_btn_grant`).onclick = () => this.grantAccess();
    this.container.querySelector(`#${this.uid}_btn_revoke`).onclick = () => this.revokeAccess();
  }

  _showError(msg) {
    const el = this.container.querySelector(`#${this.uid}_error`);
    if (el) { el.textContent = msg; el.style.display = 'block'; }
  }

  _clearError() {
    const el = this.container.querySelector(`#${this.uid}_error`);
    if (el) { el.style.display = 'none'; el.textContent = ''; }
  }

  async grantAccess() {
    this._clearError();
    const durationEl = this.container.querySelector(`#${this.uid}_duration`);
    const duration = parseInt(durationEl.value);

    let res, data;
    try {
      res = await fetch(`${this.apiBase}/grant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Send camelCase key to match server DTO (F-1-A fix).
        body: JSON.stringify({ durationMinutes: duration })
      });
    } catch (networkErr) {
      this._showError('Network error: ' + networkErr.message);
      return;
    }

    if (!res.ok) {
      // Check res.ok BEFORE calling res.json() (F-7-C fix).
      let errMsg = `Server error ${res.status}`;
      try {
        const errBody = await res.json();
        errMsg = errBody.detail || errBody.message || errMsg;
      } catch (_) { /* non-JSON body — use generic message */ }
      this._showError(errMsg);
      return;
    }

    try {
      data = await res.json();
    } catch (parseErr) {
      this._showError('Unexpected response format from server.');
      return;
    }

    if (data.success) {
      this.container.querySelector(`#${this.uid}_token`).textContent = data.token;
      this.container.querySelector(`#${this.uid}_output`).style.display = 'block';
    }
  }

  async revokeAccess() {
    this._clearError();

    let res, data;
    try {
      res = await fetch(`${this.apiBase}/revoke`, { method: 'POST' });
    } catch (networkErr) {
      this._showError('Network error: ' + networkErr.message);
      return;
    }

    if (!res.ok) {
      let errMsg = `Server error ${res.status}`;
      try {
        const errBody = await res.json();
        errMsg = errBody.detail || errBody.message || errMsg;
      } catch (_) { /* non-JSON body */ }
      this._showError(errMsg);
      return;
    }

    try {
      data = await res.json();
    } catch (parseErr) {
      this._showError('Unexpected response format from server.');
      return;
    }

    if (data.success) {
      alert('All support delegations revoked.');
      this.container.querySelector(`#${this.uid}_output`).style.display = 'none';
    }
  }
}
```

---

## 🧪 Verification Plan

### Build Check
```bash
go build ./...
```

### SDK Security Verification
1. Mount SDK via `engine.MountRoutes(router)` in an integration test server.
2. Send `POST /api/v1/auth/support/grant` with **no** `Authorization` header.
   Expect: `401 UNAUTHORIZED` (confirms auth middleware is active — F-7-A fix).
3. Send 11 rapid `POST /api/v1/auth/support/login` requests.
   Expect: 11th request returns `429 RATE_LIMIT_EXCEEDED` (confirms rate limiter is wired).

### Widget Multi-Instance Verification
```html
<div id="panel-a"></div>
<div id="panel-b"></div>
<script src="/grantsupport.js"></script>
<script>
  new GrantSupportWidget('panel-a', { apiBase: '/api/v1/auth/support' });
  new GrantSupportWidget('panel-b', { apiBase: '/api/v1/auth/support' });
  // Clicking "Grant" in panel-b must not affect panel-a's output div.
</script>
```
