# Phase 1 Implementation Plan: Code-Documentation Parity & Critical Bug Fixes

## 📌 Problem & Context
Phase 1 addresses the core code-documentation discrepancies and critical runtime bugs identified in GrantSupport:
1. **Support Login Agent Identity Flaw**: `SupportLoginInput` DTO only accepts `token`, causing support agent logins to execute with `user_id = 00000000-0000-0000-0000-000000000000` (nil UUID).
2. **Missing `pkg/license` Ed25519 Engine**: Documentation references Ed25519 license signature verification and seat caps, but `pkg/license/` is completely empty.
3. **Valkey Soft Bypass Vulnerability**: `main.go` catches Valkey connection errors as warnings instead of enforcing mandatory fail-closed startup behavior in production.
4. **Missing JWT Key Production Guard**: If `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY` are unset, the app silently falls back to a transient ephemeral keypair — tokens become invalid on every restart.

> **Cross-phase note (F-1-C, F-1-D)**: Phase 5 changes `NewSecurityAuditRepository`'s constructor signature (adds an `ed25519.PrivateKey` parameter) and completely rewrites `LogSecurityEvent` (drops the `*ent.Tx` parameter and changes the return type). To avoid a compile break when phases are applied in order, **Phase 1 does NOT update the `auditRepo` wiring in `main.go` beyond what is already present in the current codebase**. Phase 5 owns that entire update as a single self-contained diff, and explicitly documents every call site it touches.

> **JSON tag convention (F-1-A)**: The live codebase uses `json:"durationMinutes"` (camelCase) on `GrantSupportInput`. All plans and the Phase 7 JS widget use **camelCase** JSON keys. Do not use snake_case `duration_minutes` anywhere.

> **agent_id parse failure — authoritative behavior (finding #1)**: A malformed or missing `agentId` field returns **HTTP 400 with `code: "INVALID_AGENT_ID"`**. There is no silent random-UUID fallback. This is the single canonical behavior across all plan files.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `pkg/controller` — DTO & Controller Updates

#### [MODIFY] [auth_dto.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_dto.go)

**BEFORE:**
```go
// SupportLoginInput captures support token payload.
type SupportLoginInput struct {
	Token string `json:"token" validate:"required"`
}
```

**AFTER:**
```go
// SupportLoginInput captures support token and agent identity payload.
// AgentID is required and must be a valid UUID; a parse failure returns HTTP 400
// rather than a silent nil-UUID fallback — this is the canonical behavior across all plans.
type SupportLoginInput struct {
	Token      string `json:"token" validate:"required"`
	AgentID    string `json:"agentId" validate:"required,uuid"`
	AgentEmail string `json:"agentEmail" validate:"omitempty,email"`
}
```

**NOTE**: `GrantSupportInput.DurationMinutes` already has `json:"durationMinutes"` in the live file — no change needed. Phase 6 must preserve this camelCase tag when it adds `Reason` and `Scope` fields.

#### [MODIFY] [auth_support_controller.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_support_controller.go#L46-L74)

**BEFORE:**
```go
// SupportLogin authenticates a support agent using a valid support token.
// POST /api/v1/auth/support/login
func (c *SupportGrantController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}

	var callerID uuid.UUID
	if userID, ok := pkgctx.GetUser(r.Context()); ok {
		callerID = userID
	}

	instID, jwtToken, err := c.grantService.SupportLogin(r.Context(), input.Token, callerID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Delegated support login successful.",
		"access_token": jwtToken,
		"data": map[string]any{
			"institution_id": instID,
			"access_token":   jwtToken,
		},
	})
	return nil
}
```

**AFTER:**
```go
// SupportLogin authenticates a support agent using a valid support token.
// POST /api/v1/auth/support/login
// agentId parse failure returns HTTP 400 — reject-with-400 is the authoritative behavior
// (no silent random-UUID fallback anywhere in the codebase or plans).
func (c *SupportGrantController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}

	// uuid validate tag already enforces format; Parse here is belt-and-suspenders.
	agentUUID, err := uuid.Parse(input.AgentID)
	if err != nil {
		return NewAppError(http.StatusBadRequest, "INVALID_AGENT_ID", "agentId must be a valid UUID (v4 or v7)")
	}

	instID, jwtToken, err := c.grantService.SupportLogin(r.Context(), input.Token, agentUUID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Delegated support login successful.",
		"access_token": jwtToken,
		"role":         "SUPPORT_AGENT",
		"expires_in":   14400,
		"data": map[string]any{
			"institution_id": instID,
			"agent_id":       agentUUID,
			"access_token":   jwtToken,
		},
	})
	return nil
}
```

---

### Component 2: `pkg/license` — Ed25519 License Verification Engine with Startup Caching

#### [NEW] [manager.go](file:///d:/Hostel_management/GrantSupport/pkg/license/manager.go)

```go
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrLicenseInvalid   = errors.New("LICENSE_INVALID: Cryptographic license verification failed")
	ErrLicenseExpired   = errors.New("LICENSE_EXPIRED: License term has exceeded expiry plus grace period")
	ErrSeatLimitReached = errors.New("LICENSE_SEAT_LIMIT_EXCEEDED: Maximum support agent seat limit reached")
)

// LicenseClaims contains the verified license metadata parsed from the vendor-signed JWL token.
type LicenseClaims struct {
	LicenseID        string `json:"lic_id"`
	CustomerID       string `json:"customer_id"`
	Domain           string `json:"domain"`
	MaxHumanAgents   int    `json:"max_human_agents"`
	MaxAIAgents      int    `json:"max_ai_agents"`
	Tier             string `json:"tier"`
	ExpiresAt        int64  `json:"expires_at"`
	OfflineGraceDays int    `json:"offline_grace_days"`
}

// IsExpiredWithGrace returns true only if the license has exceeded both its hard expiry AND
// the OfflineGraceDays buffer, preventing cliff-edge failures for grants issued near expiry (F-1-B / finding #22).
func (lc *LicenseClaims) IsExpiredWithGrace() bool {
	gracePeriodEnd := lc.ExpiresAt + int64(lc.OfflineGraceDays)*86400
	return time.Now().Unix() > gracePeriodEnd
}

// Manager holds the vendor Ed25519 public key and a cached verified claims object.
// License verification is performed ONCE at startup via VerifyAndCache, not on every request.
type Manager struct {
	publicKey    ed25519.PublicKey
	mu           sync.RWMutex
	cachedClaims *LicenseClaims
}

// NewManager constructs a license manager from a base64-encoded Ed25519 public key.
func NewManager(pubKeyBase64 string) (*Manager, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 license public key: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key length")
	}
	return &Manager{publicKey: ed25519.PublicKey(keyBytes)}, nil
}

// VerifyAndCache verifies the license signature and caches the result.
// Call once at startup; use CachedClaims() thereafter.
func (m *Manager) VerifyAndCache(rawJWL string) (*LicenseClaims, error) {
	parts := strings.Split(rawJWL, ".")
	if len(parts) != 3 {
		return nil, ErrLicenseInvalid
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrLicenseInvalid
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrLicenseInvalid
	}

	if !ed25519.Verify(m.publicKey, payloadBytes, sigBytes) {
		return nil, ErrLicenseInvalid
	}

	var claims LicenseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrLicenseInvalid
	}

	// Apply OfflineGraceDays grace buffer so grants issued near expiry still allow login (finding #22).
	if claims.IsExpiredWithGrace() {
		return nil, ErrLicenseExpired
	}

	m.mu.Lock()
	m.cachedClaims = &claims
	m.mu.Unlock()

	return &claims, nil
}

// CachedClaims returns the last successfully verified license claims, or nil if
// VerifyAndCache has not been called. Callers should check for nil before using.
func (m *Manager) CachedClaims() *LicenseClaims {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedClaims
}
```

---

### Component 3: `cmd/server` — Strict Valkey Startup & JWT Production Guard

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go)

**BEFORE (JWT key block, lines 39–46):**
```go
	// Initialize RSA JWT Keys
	if err := security.LoadJWTKeysFromEnv(); err != nil {
		slog.Warn("RSA JWT keys not found in environment, generating transient keypair for runtime...")
		if err := security.SetupTestRSAKeys(); err != nil {
			slog.Error("Failed to initialize transient JWT keys", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}
```

**AFTER:**
```go
	// Initialize RSA JWT Keys — fail hard in production if keys are absent (fix #11 / F-3-B).
	if err := security.LoadJWTKeysFromEnv(); err != nil {
		if cfg.Environment == "production" {
			slog.Error("FATAL: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required in production. Exiting.",
				slog.String("error", err.Error()))
			os.Exit(1)
		}
		slog.Warn("RSA JWT keys not found, generating transient keypair (development only — NOT safe for production)...")
		if err := security.SetupTestRSAKeys(); err != nil {
			slog.Error("Failed to initialize transient JWT keys", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}
```

**BEFORE (Valkey block, lines 61–68):**
```go
	// Initialize Valkey Cache Client (Optional)
	var valkeyClient *cache.ValkeyClient
	if cfg.ValkeyCacheURL != "" {
		valkeyClient, err = cache.NewValkeyClient(cfg.ValkeyCacheURL)
		if err != nil {
			slog.Warn("Valkey connection bypass (running without distributed cache)", slog.String("error", err.Error()))
		}
	}
```

**AFTER:**
```go
	// Initialize Valkey Cache Client — mandatory in production (valkey-enforcement.md).
	var valkeyClient *cache.ValkeyClient
	if cfg.ValkeyCacheURL != "" {
		valkeyClient, err = cache.NewValkeyClient(cfg.ValkeyCacheURL)
		if err != nil {
			slog.Error("CRITICAL: Failed to connect to Valkey cache instance", slog.String("error", err.Error()))
			if cfg.Environment == "production" {
				slog.Error("FATAL: Valkey connection is MANDATORY in production mode. Exiting.")
				os.Exit(1)
			}
		}
	} else if cfg.Environment == "production" {
		slog.Error("FATAL: VALKEY_CACHE_URL environment variable is required in production. Exiting.")
		os.Exit(1)
	}
```

**auditRepo line (line 73) — UNCHANGED:**
```go
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
```
> ⚠️ **Phase ordering note**: Phase 5 changes `NewSecurityAuditRepository` to accept an `ed25519.PrivateKey` second parameter and updates this line in `main.go`. Phase 1 intentionally leaves this unchanged so `go build ./...` succeeds after Phase 1 alone.

**BEFORE (service constructor call, line 75):**
```go
	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient)
```

**AFTER (Phase 1 adds `licMgr` as 4th parameter):**
```go
	// Build license manager from env vars (Phase 1).
	// LICENSE_KEY and LICENSE_PUBLIC_KEY are REQUIRED in production for seat-limit enforcement.
	var licMgr *license.Manager
	if licKey := os.Getenv("LICENSE_KEY"); licKey != "" {
		if pubKeyB64 := os.Getenv("LICENSE_PUBLIC_KEY"); pubKeyB64 != "" {
			var licErr error
			licMgr, licErr = license.NewManager(pubKeyB64)
			if licErr == nil {
				if _, licErr = licMgr.VerifyAndCache(licKey); licErr != nil {
					slog.Warn("License verification failed; seat-limit enforcement disabled",
						slog.String("error", licErr.Error()))
					licMgr = nil
				}
			}
		}
	}
	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr)
```

Add to imports (Phase 1 additions):
```go
	"grantsupport/pkg/license"
```

> **Cross-phase call-site audit for `NewGrantSupportService` (mandatory per process rule)**:
> - `phase_1_plan.md` (this file): `NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr)` — 4 args ✔
> - `phase_6_plan.md` Component 7: Updated to `NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr, webhookDispatcher, webhookRepo)` — 6 args ✔
> - `phase_7_plan.md`: Does not call `NewGrantSupportService` — ✔
> - `implementation_plan.md`: Does not call the constructor directly — ✔
> - **Call sites checked: phase_1, phase_6. All updated: yes.**

---

### Component 4: [NEW] `.env.example` (project root)

```env
# GrantSupport Engine — Environment Variable Reference
# Copy to .env and fill in all REQUIRED values.

# ─── Server ───────────────────────────────────────────────────────────
PORT=8085
GO_ENV=development          # set to "production" for production deployments

# ─── Database ───────────────────────────────────────────────────────────
# REQUIRED
DATABASE_URL=postgresql://postgres:password@localhost:5432/grantsupport_db?sslmode=disable
# OPTIONAL — valid values: postgres | mysql | sqlite3  (default: postgres)
DATABASE_DIALECT=postgres

# ─── Valkey / Redis ──────────────────────────────────────────────────────────
# REQUIRED in production; optional in development
VALKEY_CACHE_URL=redis://127.0.0.1:6379

# ─── JWT Signing Keys (RS256) ───────────────────────────────────────────────────
# REQUIRED in production — absence causes fatal exit when GO_ENV=production.
# In development an ephemeral in-memory keypair is generated automatically.
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

# ─── Encryption ───────────────────────────────────────────────────────────────
# OPTIONAL — valid values: LOCAL | AWS_KMS  (default: LOCAL)
ENCRYPTION_PROVIDER=LOCAL
# REQUIRED when ENCRYPTION_PROVIDER=LOCAL (must not use default in production)
MASTER_ENCRYPTION_KEY=<change-me-to-a-random-32-byte-hex-string>
# REQUIRED when ENCRYPTION_PROVIDER=AWS_KMS
# KMS_KEY_ID=arn:aws:kms:ap-south-1:123456789012:key/mrk-...
# AWS_REGION=ap-south-1

# ─── License ──────────────────────────────────────────────────────────────────
# REQUIRED in production for seat-limit enforcement
LICENSE_KEY=<your-ed25519-signed-license-key-from-vendor>
LICENSE_PUBLIC_KEY=<base64-encoded-ed25519-public-key-from-vendor>

# ─── Audit Log Signing ───────────────────────────────────────────────────────────
# See Phase 5 for details on key source and rotation.
# REQUIRED when Phase 5 is deployed
# AUDIT_SIGNING_PRIVATE_KEY=<base64-encoded-ed25519-private-key>
```

---

### Component 5: `pkg/service` — Seat-Limit Enforcement at Login (Fix #3 / I-3)

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go)

**What was wrong**: `ErrSeatLimitReached` was defined in `pkg/license` but no code anywhere compared `LicenseClaims.MaxHumanAgents` against the count of live sessions.

**Fix**: `GrantSupportService` receives a `*license.Manager` at construction. `SupportLogin` counts **currently-active sessions — grants that have been consumed (`is_used=true`) and whose expiry window has not yet passed (`expires_at > NOW())** and compares against `MaxHumanAgents` before issuing the JWT.

**BEFORE (`GrantSupportService` struct, line 26):**
```go
type GrantSupportService struct {
	supportGrantRepo *repository.SupportGrantRepository
	auditRepo        *repository.SecurityAuditRepository
	valkey           *cache.ValkeyClient
}
```

**AFTER:**
```go
type GrantSupportService struct {
	supportGrantRepo *repository.SupportGrantRepository
	auditRepo        *repository.SecurityAuditRepository
	valkey           *cache.ValkeyClient
	// licenseManager provides seat-cap enforcement from the cached license claims.
	// May be nil if no license is configured (enforcement disabled).
	licenseManager   *license.Manager
}
```

**BEFORE (`NewGrantSupportService`, line 32):**
```go
func NewGrantSupportService(
	supportGrantRepo *repository.SupportGrantRepository,
	auditRepo *repository.SecurityAuditRepository,
	valkey *cache.ValkeyClient,
) *GrantSupportService {
	return &GrantSupportService{
		supportGrantRepo: supportGrantRepo,
		auditRepo:        auditRepo,
		valkey:           valkey,
	}
}
```

**AFTER (Phase 1 signature — 4 args):**
```go
func NewGrantSupportService(
	supportGrantRepo *repository.SupportGrantRepository,
	auditRepo *repository.SecurityAuditRepository,
	valkey *cache.ValkeyClient,
	licMgr *license.Manager,
) *GrantSupportService {
	return &GrantSupportService{
		supportGrantRepo: supportGrantRepo,
		auditRepo:        auditRepo,
		valkey:           valkey,
		licenseManager:   licMgr,
	}
}
```

> **Phase 6 extends this to 6 args** by adding `webhookDispatcher` and `webhookRepo`. See Phase 6's BEFORE/AFTER which takes this 4-arg version as its baseline.

**BEFORE (inside `SupportLogin`, after grant validation, line 119):**
```go
	if err := s.supportGrantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}
```

**AFTER (insert seat-limit check BEFORE MarkGrantAsUsed):**
```go
	// Seat-limit enforcement (I-3 fix / ErrSeatLimitReached from pkg/license).
	// Counts currently-active sessions: grants that have been consumed (is_used=true)
	// and whose expiry window has not yet passed (expires_at > NOW()).
	// Check is skipped when licenseManager is nil (no license configured).
	if s.licenseManager != nil {
		claims := s.licenseManager.CachedClaims()
		if claims != nil && claims.MaxHumanAgents > 0 {
			activeCount, err := s.supportGrantRepo.CountActiveGrantsForInstitution(ctx, instID)
			if err != nil {
				return uuid.Nil, "", fmt.Errorf("failed to query active seat count: %w", err)
			}
			// If AT or ABOVE the limit, reject and audit before returning.
			if activeCount >= claims.MaxHumanAgents {
				if s.auditRepo != nil {
					_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
						"SUPPORT_LOGIN_SEAT_LIMIT",
						fmt.Sprintf("Login rejected: seat cap %d reached for institution %s",
							claims.MaxHumanAgents, instID),
						nil)
				}
				return uuid.Nil, "", license.ErrSeatLimitReached
			}
		}
	}

	if err := s.supportGrantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}
```

> **`CountActiveGrantsForInstitution` repository method** — add to `SupportGrantRepository`:

```go
// CountActiveGrantsForInstitution returns the count of currently-active sessions:
// grants that have been consumed (is_used=true) and whose expiry window has not passed.
// Used to enforce LicenseClaims.MaxHumanAgents seat caps at login time.
func (r *SupportGrantRepository) CountActiveGrantsForInstitution(ctx context.Context, institutionID uuid.UUID) (int, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return 0, err
	}
	return client.SupportGrant.Query().
		Where(
			supportgrant.InstitutionID(institutionID),
			supportgrant.IsUsed(true),
			supportgrant.ExpiresAtGT(time.Now()),
		).
		Count(ctx)
}
```

---

### Component 6: `pkg/service` & `pkg/controller` — Grant-Creation Idempotency (I-5)

An optional `Idempotency-Key` header lets clients retry `POST /api/v1/auth/support/grant` safely. The server stores `idempotency:grant:<key>` in Valkey for 60 seconds, returning the original raw token on duplicate requests. This is a **non-breaking, backward-compatible addition** — clients that do not send the header get the existing behaviour.

#### [MODIFY] [auth_support_controller.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_support_controller.go) — `GrantSupport` handler

```go
// GrantSupport creates a delegated support access token for the calling institution.
// POST /api/v1/auth/support/grant (authenticated — requires admin JWT)
// Optional: send Idempotency-Key header to make retries safe.
func (c *SupportGrantController) GrantSupport(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[GrantSupportInput](r)
	if err != nil {
		return err
	}

	institutionID, ok := pkgctx.GetTenant(r.Context())
	if !ok {
		return NewAppError(http.StatusUnauthorized, "MISSING_TENANT", "institution context not found")
	}
	adminUserID, ok := pkgctx.GetUser(r.Context())
	if !ok {
		return NewAppError(http.StatusUnauthorized, "MISSING_USER", "user context not found")
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")

	rawToken, err := c.grantService.CreateSupportGrant(r.Context(), institutionID, adminUserID,
		input.DurationMinutes, idempotencyKey)
	if err != nil {
		return NewAppError(http.StatusInternalServerError, "GRANT_CREATION_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"token":   rawToken,
		"message": "Support access grant created successfully.",
	})
	return nil
}
```

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go) — `CreateSupportGrant`

**BEFORE (signature):**
```go
func (s *GrantSupportService) CreateSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int) (string, error) {
```

**AFTER (add optional idempotency key parameter):**
```go
// CreateSupportGrant creates a temporary support access token.
// idempotencyKey is optional (empty string = disabled). When provided, a repeated call
// within 60 seconds returns the original token instead of creating a new row.
func (s *GrantSupportService) CreateSupportGrant(
	ctx context.Context,
	institutionID, adminUserID uuid.UUID,
	durationMinutes int,
	idempotencyKey string,
) (string, error) {
	// Idempotency check — runs before the Redlock to short-circuit quickly.
	if idempotencyKey != "" && s.valkey != nil && s.valkey.Client != nil {
		valkeyKey := fmt.Sprintf("idempotency:grant:%s", idempotencyKey)
		if existingToken, err := s.valkey.Client.Get(ctx, valkeyKey).Result(); err == nil {
			// Duplicate request — return the original token without a DB write.
			return existingToken, nil
		}
	}

	// ... (rest of existing grant creation logic unchanged) ...

	// After successful grant creation, store idempotency mapping with 60-second TTL.
	if idempotencyKey != "" && s.valkey != nil && s.valkey.Client != nil {
		valkeyKey := fmt.Sprintf("idempotency:grant:%s", idempotencyKey)
		_ = s.valkey.Client.Set(ctx, valkeyKey, rawToken, 60*time.Second).Err()
	}

	return rawToken, nil
}
```

> **Cross-phase call-site audit for `CreateSupportGrant` (mandatory per process rule — N-3 fix)**:
> The I-5 fix adds `idempotencyKey string` as a 5th parameter to `CreateSupportGrant`. Every call site across all 7 phase files and implementation_plan.md was searched for the string `"CreateSupportGrant"`:
>
> | File | Line | Nature | Status |
> |---|---|---|---|
> | `phase_1_plan.md` (controller, this file) | 545–546 | External call — controller passes `idempotencyKey` | ✅ 5-arg, correct |
> | `phase_1_plan.md` (service BEFORE block) | 564 | Shows pre-I-5 state for diff clarity | ✅ BEFORE block only |
> | `phase_1_plan.md` (service AFTER block) | 572–577 | Service method definition | ✅ 5-arg, correct |
> | `phase_6_plan.md` | 556–567 | Internal webhook dispatch code **inside** `CreateSupportGrant` body — not a call to it | ✅ Not a call site |
> | `phase_2_plan.md`, `phase_3_plan.md`, `phase_4_plan.md`, `phase_5_plan.md`, `phase_7_plan.md`, `implementation_plan.md` | — | No reference to `CreateSupportGrant` | ✅ No call sites |
>
> **Call sites checked: all 7 phase files + implementation_plan.md. All updated: yes.**

---

## 🧪 Verification Plan

### Build Check (after Phase 1 only — must pass before Phase 2)
```bash
go build ./...
```
Expect: zero errors. The `auditRepo` constructor is unchanged; `NewGrantSupportService` is now 4-arg.

### Automated Unit Tests
```bash
go test ./pkg/license/... -v
go test ./pkg/controller/... -v
```

### Manual Verification
1. Send `POST /api/v1/auth/support/login` with malformed `agentId`:
   ```json
   { "token": "inst_123_abc...", "agentId": "not-a-uuid" }
   ```
   Expect: `400 Bad Request`, `code: "INVALID_AGENT_ID"`.

2. Send with valid `agentId`:
   ```json
   { "token": "inst_123_abc...", "agentId": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11" }
   ```
   Expect: `200 OK` with `agent_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"` in response.

3. Send `POST /api/v1/auth/support/grant` with `Idempotency-Key: my-key-abc` twice rapidly.
   Expect: both return the same `token` value; only one `SupportGrant` row created in DB.

4. When `MaxHumanAgents=2` in license and 2 sessions are active:
   Attempt a 3rd `POST /api/v1/auth/support/login`.
   Expect: `401 LICENSE_SEAT_LIMIT_EXCEEDED` and `SUPPORT_LOGIN_SEAT_LIMIT` audit entry created.
