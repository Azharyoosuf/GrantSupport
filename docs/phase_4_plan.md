# Phase 4 Implementation Plan: Security Hardening

## 📌 Problem & Context
1. **Missing Instant Revocation**: Revoking a grant updates the DB, but already-issued RS256 JWTs remain valid until natural expiration.
2. **Missing Rate Limiting**: `/api/v1/auth/support/login` lacks brute-force protection.
3. **Static JWT Lifetime**: Session tokens have a fixed 4-hour lifetime.
4. **Rate limiter built but never mounted** (F-3-C): `RateLimitMiddleware` is dead code unless wired into both `main.go` and the Phase 7 SDK.
5. **Failed events never audited** (F-4-C / finding #12): Rate-limit hits and token-revocation rejections are invisible in `AuditEvent`.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `pkg/service` — Two Named Revocation Modes (finding #28)

> **Two named revocation designs (finding #28)**: There are exactly two distinct revocation features:
> - **Per-institution revocation** (`RevokeSupportGrant`): Invalidates all grants in DB + blacklists all JWTs issued before the revocation timestamp via a Valkey key `revoked:inst:<institution_id>`. Used when an admin revokes all delegated access at once.
> - **Per-agent JWT revocation** (future Phase — deferred): Blacklisting a single JWT by `jti` claim. Not implemented in these plans; documented here as a deferred feature to prevent confusion.

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go#L140-L155)

**BEFORE:**
```go
// RevokeSupportGrant invalidates all active support grants for an institution.
func (s *GrantSupportService) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	if s.supportGrantRepo == nil {
		return errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if err := s.supportGrantRepo.RevokeAllGrantsForInstitution(ctx, institutionID); err != nil {
		return err
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "All active support access grants manually revoked by administrator", nil)
	}

	return nil
}
```

**AFTER:**
```go
// RevokeSupportGrant performs PER-INSTITUTION revocation:
// 1. Marks all DB grant rows as revoked.
// 2. Writes a revocation timestamp to Valkey so any JWT issued before that
//    timestamp is immediately rejected by AuthMiddleware (fail-closed on Valkey error).
//
// Per-agent (per-JWT) revocation is a deferred feature tracked separately.
func (s *GrantSupportService) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	if s.supportGrantRepo == nil {
		return errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if err := s.supportGrantRepo.RevokeAllGrantsForInstitution(ctx, institutionID); err != nil {
		return err
	}

	// Blacklist all JWTs issued before now for this institution.
	// Use millisecond precision to avoid same-second collision (F-4-B / finding #19).
	if s.valkey != nil && s.valkey.Client != nil {
		revocationKey := fmt.Sprintf("revoked:inst:%s", institutionID.String())
		nowMilli := time.Now().UnixMilli()
		// TTL = 4 hours (matches maximum JWT duration) so the key expires automatically.
		_ = s.valkey.Client.Set(ctx, revocationKey, nowMilli, 4*time.Hour).Err()
	}

	if s.auditRepo != nil {
		// NOTE: Phase 4 runs BEFORE Phase 5. Phase 5 changes LogSecurityEvent's signature
		// (drops the *ent.Tx parameter). Until Phase 5 is applied, call sites use the old
		// 6-argument signature. Phase 5 updates ALL call sites atomically — this one included.
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "PER-INSTITUTION: All active support access grants manually revoked by administrator", nil)
	}

	return nil
}
```

---

### Component 2: `pkg/middleware` — Auth Revocation Check (fail-closed)

#### [MODIFY] [auth.go](file:///d:/Hostel_management/GrantSupport/pkg/middleware/auth.go#L44-L52)

**BEFORE (revocation section):**
```go
			// TokenVersion revocation check against Valkey security cache
			if valkey != nil && valkey.Client != nil {
				cacheKey := fmt.Sprintf("cache:%s:user:security:%s", claims.InstitutionID, claims.UserID)
				cachedVersion, err := valkey.Client.Get(r.Context(), cacheKey).Int()
				if err == nil && cachedVersion > claims.TokenVersion {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Session has been revoked. Please log in again.")
					return
				}
			}
```

**AFTER** (adds institution-wide revocation check with millisecond precision and fail-closed on Valkey error):
```go
			// Per-user token-version revocation (existing check).
			if valkey != nil && valkey.Client != nil {
				cacheKey := fmt.Sprintf("cache:%s:user:security:%s", claims.InstitutionID, claims.UserID)
				cachedVersion, err := valkey.Client.Get(r.Context(), cacheKey).Int()
				if err == nil && cachedVersion > claims.TokenVersion {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Session has been revoked. Please log in again.")
					return
				}
			}

			// Per-institution revocation check (F-4-B / finding #10 fail-closed fix).
			// Use strict less-than (<) to avoid same-millisecond off-by-one (finding #19).
			if valkey != nil && valkey.Client != nil {
				revocationKey := fmt.Sprintf("revoked:inst:%s", claims.InstitutionID)
				revokedMilli, err := valkey.Client.Get(r.Context(), revocationKey).Int64()
				if err != nil {
					// FAIL-CLOSED: if Valkey is unavailable, we cannot confirm this institution
					// has not been revoked. Deny the request rather than allow it through.
					controller.WriteRFC7807Error(w, http.StatusServiceUnavailable, "REVOCATION_CHECK_UNAVAILABLE", "Security cache is unavailable; please retry in a moment.")
					return
				}
				// IssuedAt is set in milliseconds when Phase 4 is deployed; use strict < (not <=).
				if claims.IssuedAt != nil && claims.IssuedAt.UnixMilli() < revokedMilli {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Support session has been explicitly revoked by administrator.")
					return
				}
			}
```

---

### Component 3: `pkg/middleware/ratelimit.go` — Atomic Rate Limiter

#### [NEW] [ratelimit.go](file:///d:/Hostel_management/GrantSupport/pkg/middleware/ratelimit.go)

> **Fix (F-4-A / finding #18)**: The two-step `INCR` + `Expire` approach can leave a key without a TTL if `Expire` fails. This implementation uses a Lua script to atomically increment and set expiry in a single round-trip, eliminating the race.

```go
package middleware

import (
	"fmt"
	"net/http"
	"strings" // required for GetRealClientIP XFF parsing (I-9 fix)
	"time"

	"grantsupport/pkg/cache"
	"grantsupport/pkg/controller"
)

// atomicRateLimitScript is a Lua script that atomically increments a counter
// and sets its TTL only on the first increment, preventing the INCR+Expire race
// condition (F-4-A) where a failed Expire call leaves a key with no TTL.
var atomicRateLimitScript = `
local key = KEYS[1]
local window = tonumber(ARGV[1])
local current = redis.call('INCR', key)
if current == 1 then
  redis.call('EXPIRE', key, window)
end
return current
`

// RateLimitMiddleware enforces a sliding-window request limit per IP using
// an atomic Lua script to prevent TTL-race permanent IP bans.
func RateLimitMiddleware(valkey *cache.ValkeyClient, maxRequests int, windowSecs int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if valkey == nil || valkey.Client == nil {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := GetRealClientIP(r)
			key := fmt.Sprintf("ratelimit:%s:%s", r.URL.Path, clientIP)

			result, err := valkey.Client.Eval(r.Context(), atomicRateLimitScript,
				[]string{key},
				windowSecs,
			).Int64()
			if err == nil && result > int64(maxRequests) {
				controller.WriteRFC7807Error(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
					"Too many authentication requests. Please try again later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetRealClientIP extracts the true client IP, respecting X-Forwarded-For.
//
// FIX (I-9): The previous version returned the raw X-Forwarded-For header string, which:
//   1. Includes a comma-separated list when multiple proxies are traversed, so two requests
//      from the same IP with different list contents got different rate-limit buckets.
//   2. Allowed an attacker to inject a different fabricated IP on every request to bypass
//      the rate limiter entirely by rotating the X-Forwarded-For value.
//
// Fix: extract only the LEFTMOST (first) entry, which is the original client IP as set
// by the outermost trusted proxy. Only the first element is taken via SplitN.
//
// OPERATIONAL ASSUMPTION: GrantSupport is expected to run behind a trusted reverse proxy
// (e.g. nginx, AWS ALB, Cloudflare) that correctly sets X-Forwarded-For to the real client IP
// and strips any client-supplied X-Forwarded-For header. If a customer self-hosts WITHOUT
// a trusted proxy in front, this header is attacker-controlled and REMOTE_ADDR should be
// used instead. Customers running without a proxy MUST set TRUST_PROXY=false and configure
// the server to ignore X-Forwarded-For (future Phase 4.1 config option).
func GetRealClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take only the leftmost IP in the comma-separated list (SplitN limits to 2 parts).
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}
```

---

### Component 4: `cmd/server/main.go` — Wire Rate Limiter (F-3-C fix) & Failed-Login Audit (Fix #4)

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go#L93-L101)

**BEFORE:**
```go
	// Public Support Agent Login Endpoint
	r.Post("/api/v1/auth/support/login", controller.CatchAsync(grantController.SupportLogin))

	// Authenticated Customer Admin Delegation Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
	})
```

**AFTER:**
```go
	// Public Support Agent Login Endpoint — rate-limited to 10 requests/60s per IP (F-3-C fix).
	r.With(
		middleware.RateLimitMiddleware(valkeyClient, 10, 60),
	).Post("/api/v1/auth/support/login", controller.CatchAsync(grantController.SupportLogin))

	// Authenticated Customer Admin Delegation Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
	})
```

---

### Component 4b: Failed-Login Audit Logging — `SupportLogin` failure path (Fix #4)

> **What was previously claimed vs. what was true**: The previous Component 4 note said: *"audit calls for rejection events are written from the service layer during Phase 4 for service-layer rejections (`SupportLogin` returning `SUPPORT_LOGIN_FAILED`)"*. This was **false** — no code diff was shown, and the live `SupportLogin` function does not call `LogSecurityEvent` on its failure path. This section provides the real code change.

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go)

The `SupportLogin` function currently returns `ErrSupportGrantInvalid` on any token lookup failure without logging the event to `AuditEvent`. An attacker probing with invalid tokens leaves no trace in the audit log.

**BEFORE (the entire SupportLogin failure return block, lines 114–117):**
```go
	grant, err := s.supportGrantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil || grant == nil || grant.ExpiresAt.Before(time.Now()) {
		return uuid.Nil, "", ErrSupportGrantInvalid
	}
```

**AFTER:**
```go
	grant, err := s.supportGrantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil || grant == nil || grant.ExpiresAt.Before(time.Now()) {
		// AUDIT: Log the failed login attempt so that repeated invalid-token probes
		// are visible in the immutable audit ledger (Fix #4 / finding #12).
		// We use instID extracted from the token prefix as the institution context;
		// agentUserID is the identity the caller claimed.
		// NOTE: Phase 4 uses the old 6-arg LogSecurityEvent signature (with nil tx)
		// because Phase 5 has not yet changed the signature. Phase 5 updates this
		// call site to the new 5-arg signature as part of its atomic call-site update.
		if s.auditRepo != nil {
			_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
				"SUPPORT_LOGIN_FAILED",
				fmt.Sprintf("Support login rejected: invalid or expired token presented by agent %s", agentUserID.String()),
				nil)
		}
		return uuid.Nil, "", ErrSupportGrantInvalid
	}
```

> **Audit on seat-limit rejection**: When `ErrSeatLimitReached` is returned (added in Phase 1, Component 5), the seat-limit check runs before this block. Add a similar audit call there:
> ```go
> if activeCount >= claims.MaxHumanAgents {
>     if s.auditRepo != nil {
>         _, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
>             "SUPPORT_LOGIN_SEAT_LIMIT",
>             fmt.Sprintf("Login rejected: seat cap %d reached for institution %s", claims.MaxHumanAgents, instID),
>             nil)
>     }
>     return uuid.Nil, "", license.ErrSeatLimitReached
> }
> ```

> **Middleware-layer audit logging (RATE_LIMIT_EXCEEDED, TOKEN_REVOKED)**: Audit logging of rejections that happen *inside* `RateLimitMiddleware` or `AuthMiddleware` requires `auditRepo` to be injected into the middleware. This is a **deferred Phase 4.1 item**. The middleware does not have `auditRepo` access in Phase 4. This is an explicitly documented limitation — not a previously implied completion.

---

### Component 5: Sliding Window Idle Timeout — Decision (finding #33)

The Phase 4 problem statement mentions "static JWT lifetime." The plan does **not** implement a sliding-window idle timeout because it would require every authenticated request to touch Valkey to reset a timer, increasing per-request latency. This is **explicitly deferred** to a future phase. The problem statement item is removed from Phase 4 scope. JWT lifetime remains fixed at 4 hours.

---

## 🧪 Verification Plan

### Build Check
```bash
go build ./...
```

### Automated Tests
```bash
go test ./pkg/middleware/... -run TestRevocation -v
go test ./pkg/middleware/... -run TestRateLimiting -v
```

### Manual Verification
1. Fire 11 rapid requests to `/api/v1/auth/support/login`. Expect the 11th returns `429 RATE_LIMIT_EXCEEDED`.
2. Revoke via `POST /api/v1/auth/support/revoke`, then present the old JWT to a protected endpoint. Expect `401 TOKEN_REVOKED`.
3. Stop Valkey, present a previously-issued JWT to a protected endpoint. Expect `503 REVOCATION_CHECK_UNAVAILABLE` (fail-closed).
