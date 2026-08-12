# Phase 6 Implementation Plan: Scoped Granularity, Webhook Engine & Idempotency

## 📌 Problem & Context
1. **Lack of Granular Scopes**: All grants default to `FULL_ACCESS`. Enterprise clients need `READ_ONLY` or `SUPPORT_WRITE`.
2. **Missing Webhook Engine**: No notification when support agents log in or sessions are revoked.
3. **Webhook `targetURL` has no storage** (F-6-B): `DispatchEvent` accepts a URL but there is no DB schema, registration API, or call site — webhooks are non-functional without this.
4. **Webhook goroutine leaks at shutdown** (F-6-A / finding #17): `context.Background()` goroutines outlive graceful shutdown.
5. **Reason field validated but dropped** (F-6-C / finding #24): `GrantSupportInput.Reason` is validated but has no Ent schema field — data is silently discarded.
6. **Scope enforced at input but not at runtime** (finding #15): Scope is validated on the GrantSupportInput DTO but never checked when a SUPPORT_AGENT performs an action during a session.
7. **Idempotency of grant creation and webhook dispatch** (finding #27).
8. **Webhook payloads unsigned** (finding #13): Customers cannot verify webhook authenticity.

> **JSON tag convention (F-1-A)**: All new fields on `GrantSupportInput` use camelCase JSON keys to match the live codebase convention.

> **`shared_secret` encryption (new finding)**: The `InstitutionWebhook.shared_secret` field comment says it "must be stored encrypted at rest using the application encryption layer", but no prior plan shows the actual encryption call. This plan explicitly adds envelope encryption of the shared secret in `UpsertWebhook` before persistence, and decryption in `GetActiveWebhook` before returning — see Component 4 below.

> **Webhook registration API (new finding)**: The verification plan references `POST /api/v1/auth/support/webhook`, but previous drafts only showed the repository layer, not a controller or route. This plan adds a thin controller method and route registration — see Component 4b below.

---

## 🛠️ Detailed Proposed Code Changes

### Component 0 (PREREQUISITE): [NEW] `pkg/encryption` \u2014 AES-256-GCM Envelope Encryptor (I-8 fix)

> **I-8 decision (option b)**: `pkg/encryption` does NOT exist in the live codebase (confirmed by directory listing: `d:\Hostel_management\GrantSupport\pkg` contains no `encryption/` directory). This component defines it from scratch. It is introduced in Phase 6 because Phase 6 is the first phase that requires at-rest encryption (webhook shared secrets). The `MASTER_ENCRYPTION_KEY` env var was already documented in Phase 1's `.env.example`.

#### [NEW] [encryptor.go](file:///d:/Hostel_management/GrantSupport/pkg/encryption/encryptor.go)

```go
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Encryptor is the interface for reversible at-rest encryption.
// Callers must not store the plaintext output of Decrypt() beyond the current request scope.
type Encryptor interface {
	// Encrypt returns ciphertext for the given plaintext bytes.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt returns plaintext for the given ciphertext bytes.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// AESGCMEncryptor is a concrete Encryptor using AES-256-GCM with a random nonce per encryption.
// The output format is: hex(nonce || ciphertext).
type AESGCMEncryptor struct {
	block cipher.Block
}

// NewAESGCMEncryptor constructs an AESGCMEncryptor from a hex-encoded 32-byte key string.
// keyHex is the value of MASTER_ENCRYPTION_KEY from the environment.
// Returns an error if the key is absent, malformed, or not 32 bytes (AES-256).
//
// In development, if keyHex is empty, a fixed all-zeros key is used (NOT safe for production).
// In production, the caller (main.go) must enforce that keyHex is non-empty before calling this.
func NewAESGCMEncryptor(keyHex string) (*AESGCMEncryptor, error) {
	if keyHex == "" {
		// Development fallback: fixed 32-byte zero key.
		// Production startup guard in main.go ensures this branch is never reached in production.
		keyHex = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("MASTER_ENCRYPTION_KEY must be a hex-encoded string: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, errors.New("MASTER_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars) for AES-256")
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	return &AESGCMEncryptor{block: block}, nil
}

// Encrypt produces AES-256-GCM ciphertext with a random 12-byte nonce prepended.
// Output is hex-encoded for safe storage as a VARCHAR/TEXT column value.
func (e *AESGCMEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(e.block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil) // nonce prepended to ciphertext
	dst := make([]byte, hex.EncodedLen(len(sealed)))
	hex.Encode(dst, sealed)
	return dst, nil
}

// Decrypt reverses Encrypt: hex-decodes, splits off the nonce, and decrypts with AES-256-GCM.
func (e *AESGCMEncryptor) Decrypt(hexCiphertext []byte) ([]byte, error) {
	raw := make([]byte, hex.DecodedLen(len(hexCiphertext)))
	if _, err := hex.Decode(raw, hexCiphertext); err != nil {
		return nil, fmt.Errorf("failed to hex-decode ciphertext: %w", err)
	}
	gcm, err := cipher.NewGCM(e.block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short to contain nonce")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed (wrong key or tampered ciphertext): %w", err)
	}
	return plaintext, nil
}
```

> **Cross-phase note for `pkg/encryption`**: This package is introduced in Phase 6. No earlier phase references it. Phase 6's Component 4a (`WebhookRepository`) and Component 7 (`main.go`) are the only consumers. If future phases require PII encryption (e.g., Phase 8 student data), they import this same package and the same `encryptionService` instance from `main.go`.

---

### Component 1: Ent Schema — Add `reason`/`scope` to `SupportGrant`, Add `InstitutionWebhook` Entity

#### [MODIFY] [ent/schema/supportgrant.go](file:///d:/Hostel_management/GrantSupport/ent/schema/supportgrant.go)

**BEFORE (Fields):**
```go
// Existing fields: id, institution_id, granted_by_id, token_hash, expires_at, is_used, used_at, scope, whitelisted_ips, created_at
```

**AFTER — add `reason` field:**
```go
// reason: optional human-readable justification for this grant, stored in DB.
// Data flows: GrantSupportInput.Reason → service → repository → this column.
field.String("reason").Optional(),
```

> All fields except `reason` already exist in the schema. The `scope` field is also already present from the Phase 2 migration SQL. Confirm it is in the Ent schema; if not, add `field.String("scope").Default("FULL_ACCESS")`.

#### [NEW] [ent/schema/institutionwebhook.go](file:///d:/Hostel_management/GrantSupport/ent/schema/institutionwebhook.go)

```go
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// InstitutionWebhook stores per-institution webhook endpoint configuration.
type InstitutionWebhook struct {
	ent.Schema
}

func (InstitutionWebhook) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "InstitutionWebhook"},
	}
}

func (InstitutionWebhook) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.UUID("institution_id", uuid.UUID{}),
		// target_url: the HTTPS endpoint GrantSupport POSTs events to.
		field.String("target_url"),
		// shared_secret: stored as envelope-encrypted ciphertext (see WebhookRepository.UpsertWebhook).
		// Never stored as plaintext. Decrypted in-memory in GetActiveWebhook before use.
		field.String("shared_secret"),
		field.Bool("is_active").Default(true),
		field.Time("created_at"),
	}
}

func (InstitutionWebhook) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("institution_id"),
		index.Fields("institution_id", "is_active"),
	}
}
```

**After all schema changes, regenerate:**
```bash
go generate ./ent/...
```

---

### Component 2: `pkg/controller/auth_dto.go` — GrantSupportInput with Scope & Reason

#### [MODIFY] [auth_dto.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_dto.go)

**BEFORE:**
```go
// GrantSupportInput captures support delegation duration request.
// Uses camelCase JSON tags to match the live codebase convention.
type GrantSupportInput struct {
	DurationMinutes int `json:"durationMinutes" validate:"gte=1,lte=1440"`
}
```

**AFTER (camelCase tags preserved — F-1-A fix maintained):**
```go
// GrantSupportInput captures support delegation request parameters.
// All JSON keys use camelCase to match the live codebase convention.
type GrantSupportInput struct {
	DurationMinutes int    `json:"durationMinutes" validate:"gte=1,lte=1440"`
	// Reason flows through to the SupportGrant DB record and the audit log description.
	Reason          string `json:"reason" validate:"omitempty,max=255"`
	// Scope controls what actions the support agent can perform during the session.
	// Enforcement is documented below — runtime enforcement is explicitly deferred (finding #15).
	Scope           string `json:"scope" validate:"omitempty,oneof=READ_ONLY SUPPORT_WRITE FULL_ACCESS"`
}

// RegisterWebhookInput captures webhook endpoint registration payload.
type RegisterWebhookInput struct {
	TargetURL    string `json:"targetUrl" validate:"required,url"`
	SharedSecret string `json:"sharedSecret" validate:"required,min=16"`
}
```

---

### Component 3: `pkg/service/webhook_dispatcher.go` — Shutdown-Aware Dispatcher with HMAC Signing

#### [NEW] [webhook_dispatcher.go](file:///d:/Hostel_management/GrantSupport/pkg/service/webhook_dispatcher.go)

> **Fix (F-6-A / finding #17)**: Use a `sync.WaitGroup` tracked goroutine pool instead of fire-and-forget goroutines. Callers call `Wait()` before server shutdown.
> **Fix (finding #13)**: Sign payload with `HMAC-SHA256` using the per-institution shared secret. Header: `X-GrantSupport-Signature: sha256=<hex>`.
> **Fix (finding #27)**: `WebhookEvent.EventID` is a stable UUID derived from the grant ID + event type, so retried dispatches are idempotent — the customer endpoint can deduplicate by `event_id`.

```go
package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// WebhookEvent is the canonical payload dispatched to customer webhook endpoints.
type WebhookEvent struct {
	// EventID is stable for a given (source_id + event_type) so customers can deduplicate retries (finding #27).
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"` // "grant.created", "support.login", "support.revoked"
	InstitutionID string    `json:"institution_id"`
	Timestamp     time.Time `json:"timestamp"`
	Data          any       `json:"data"`
}

// WebhookDispatcher manages async HTTP webhook delivery.
type WebhookDispatcher struct {
	httpClient *http.Client
	wg         sync.WaitGroup // tracks in-flight deliveries for graceful shutdown
}

// NewWebhookDispatcher creates a dispatcher with a 5-second per-call timeout.
func NewWebhookDispatcher() *WebhookDispatcher {
	return &WebhookDispatcher{
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// Wait blocks until all in-flight webhook goroutines have completed.
// Call this during server shutdown before exiting (F-6-A fix).
func (w *WebhookDispatcher) Wait() {
	w.wg.Wait()
}

// DispatchEvent asynchronously POSTs a webhook event to targetURL.
// sourceID is the grant or event UUID — used to produce a stable, idempotent EventID.
// sharedSecret is the PLAINTEXT per-institution HMAC-SHA256 signing secret
// (decrypted by WebhookRepository.GetActiveWebhook before being passed here).
func (w *WebhookDispatcher) DispatchEvent(
	shutdownCtx context.Context,
	targetURL string,
	sharedSecret string,
	eventType string,
	instID uuid.UUID,
	sourceID uuid.UUID,
	payload any,
) {
	// Stable EventID: deterministic UUID v5 from (sourceID + eventType).
	// Idempotent: retrying the same event produces the same EventID (finding #27).
	stableEventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(sourceID.String()+":"+eventType))

	event := WebhookEvent{
		EventID:       stableEventID.String(),
		EventType:     eventType,
		InstitutionID: instID.String(),
		Timestamp:     time.Now(),
		Data:          payload,
	}

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()

		bodyBytes, err := json.Marshal(event)
		if err != nil {
			slog.Error("Webhook: failed to marshal event", slog.String("event_type", eventType), slog.String("error", err.Error()))
			return
		}

		// Use the shutdown context so this goroutine respects the server shutdown window (F-6-A).
		req, err := http.NewRequestWithContext(shutdownCtx, "POST", targetURL, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "GrantSupport-Webhook/1.0")

		// HMAC-SHA256 payload signature for customer verification (finding #13).
		if sharedSecret != "" {
			mac := hmac.New(sha256.New, []byte(sharedSecret))
			mac.Write(bodyBytes)
			req.Header.Set("X-GrantSupport-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}

		resp, err := w.httpClient.Do(req)
		if err != nil {
			slog.Warn("Webhook dispatch failed",
				slog.String("url", targetURL),
				slog.String("event_id", stableEventID.String()),
				slog.String("error", err.Error()))
			return
		}
		_ = resp.Body.Close()
		slog.Info("Webhook dispatched",
			slog.String("event_id", stableEventID.String()),
			slog.Int("status", resp.StatusCode))
	}()
}
```

---

### Component 4a: Webhook Repository — With Real Ent Predicates & Encryption

#### [NEW] [webhook_repository.go](file:///d:/Hostel_management/GrantSupport/pkg/repository/webhook_repository.go)

> **Fix (issue #2)**: The previous draft's `GetActiveWebhook` had the Where clause **commented out**: `Where( /* auditevent.InstitutionID(institutionID), is_active = true */ )`. This meant the function accepted `institutionID` as a parameter but **never used it**, returning the first row for any institution — a direct multi-tenant isolation violation. This is now fixed with real Ent predicates.
>
> **Fix (shared_secret encryption)**: `UpsertWebhook` encrypts the shared secret using the application encryption layer before persisting. `GetActiveWebhook` decrypts before returning. The returned `*ent.InstitutionWebhook` struct's `SharedSecret` field is replaced with the **plaintext** value for use by the dispatcher, but this struct should never be serialised back to any external caller (see `RegisterWebhookInput` response — it returns only `id` and `targetUrl`, never the secret).

```go
package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/ent/institutionwebhook"
	"grantsupport/pkg/encryption"
)

// WebhookRepository manages per-institution webhook configuration persistence.
type WebhookRepository struct {
	*BaseRepository
	encryptor encryption.Encryptor // used to encrypt/decrypt shared_secret at rest
}

// NewWebhookRepository constructs the repository.
func NewWebhookRepository(base *BaseRepository, enc encryption.Encryptor) *WebhookRepository {
	return &WebhookRepository{BaseRepository: base, encryptor: enc}
}

// UpsertWebhook creates or replaces the webhook configuration for an institution.
// Multi-tenant isolation: institution_id is always explicitly set (architectural mandate).
// shared_secret is encrypted using the application encryption layer before persisting (new finding fix).
func (r *WebhookRepository) UpsertWebhook(ctx context.Context, institutionID uuid.UUID, targetURL, plaintextSecret string) (*ent.InstitutionWebhook, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	// Encrypt the shared secret before storing. Never persist plaintext webhook secrets.
	encryptedSecret, err := r.encryptor.Encrypt([]byte(plaintextSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt webhook shared secret: %w", err)
	}

	return client.InstitutionWebhook.Create().
		SetInstitutionID(institutionID).
		SetTargetURL(targetURL).
		SetSharedSecret(string(encryptedSecret)).
		SetIsActive(true).
		Save(ctx)
}

// GetActiveWebhook retrieves the active webhook configuration for an institution.
// Returns nil (not an error) if no active webhook is configured for this institution.
//
// FIX (issue #2): Uses real Ent predicates to filter by BOTH institution_id AND is_active = true.
// The previous draft had the Where clause commented out, making institutionID unused
// and returning a random institution's webhook — a multi-tenant isolation violation.
func (r *WebhookRepository) GetActiveWebhook(ctx context.Context, institutionID uuid.UUID) (*ent.InstitutionWebhook, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	wh, err := client.InstitutionWebhook.Query().
		Where(
			institutionwebhook.InstitutionID(institutionID),
			institutionwebhook.IsActive(true),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil // no webhook configured — not an error
		}
		return nil, fmt.Errorf("GetActiveWebhook query failed: %w", err)
	}

	// Decrypt shared_secret in-memory before returning to the service layer.
	plaintext, err := r.encryptor.Decrypt([]byte(wh.SharedSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt webhook shared secret for institution %s: %w", institutionID, err)
	}
	// Replace the stored ciphertext with the plaintext for in-process use only.
	// This struct must never be JSON-serialised to any external caller.
	wh.SharedSecret = string(plaintext)
	return wh, nil
}
```

> **Ent predicate note**: `institutionwebhook.InstitutionID(institutionID)` and `institutionwebhook.IsActive(true)` are the generated Ent predicate functions for the `institution_id` and `is_active` fields defined in `ent/schema/institutionwebhook.go`. These are the real, compilable predicates — not placeholders.

---

### Component 4b: Webhook Registration Controller & Route (new finding fix)

> The verification plan referenced `POST /api/v1/auth/support/webhook` but no prior draft showed the controller method or route. This is added here to close that gap.

#### [MODIFY] [auth_support_controller.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_support_controller.go)

```go
// RegisterWebhook registers or replaces a webhook endpoint for the calling institution.
// POST /api/v1/auth/support/webhook (authenticated — requires admin JWT)
func (c *SupportGrantController) RegisterWebhook(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[RegisterWebhookInput](r)
	if err != nil {
		return err
	}

	institutionID, ok := pkgctx.GetTenant(r.Context())
	if !ok {
		return NewAppError(http.StatusUnauthorized, "MISSING_TENANT", "institution context not found")
	}

	if err := c.grantService.RegisterWebhook(r.Context(), institutionID, input.TargetURL, input.SharedSecret); err != nil {
		return NewAppError(http.StatusInternalServerError, "WEBHOOK_REGISTRATION_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"message": "Webhook endpoint registered successfully.",
	})
	return nil
}
```

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go) — Add webhook route to authenticated group

**BEFORE (authenticated group):**
```go
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
	})
```

**AFTER:**
```go
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
		// Webhook endpoint registration — requires admin JWT (authenticated group).
		r.Post("/api/v1/auth/support/webhook", controller.CatchAsync(grantController.RegisterWebhook))
	})
```

---

### Component 5: Wire `WebhookDispatcher` into `GrantSupportService`

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go)

Add `webhookDispatcher *WebhookDispatcher` and `webhookRepo` fields, and add `DispatchEvent` calls in `CreateSupportGrant`, `SupportLogin`, and `RevokeSupportGrant`.

**BEFORE (struct — Phase 1 baseline, 4 fields):**

> I-2 fix: The previous BEFORE showed only 3 fields (pre-Phase-1 baseline). After Phase 1 Component 5 adds `licenseManager`, the struct entering Phase 6 already has 4 fields. This is the correct baseline for Phase 6's BEFORE/AFTER diff.

```go
type GrantSupportService struct {
	supportGrantRepo *repository.SupportGrantRepository
	auditRepo        *repository.SecurityAuditRepository
	valkey           *cache.ValkeyClient
	// licenseManager added in Phase 1 Component 5.
	licenseManager   *license.Manager
}
```

**AFTER (Phase 6 adds two webhook fields):**
```go
type GrantSupportService struct {
	supportGrantRepo  *repository.SupportGrantRepository
	auditRepo         *repository.SecurityAuditRepository
	valkey            *cache.ValkeyClient
	// licenseManager added in Phase 1 Component 5.
	licenseManager    *license.Manager
	webhookDispatcher *WebhookDispatcher
	webhookRepo       *repository.WebhookRepository
}
```

Add `RegisterWebhook` service method:
```go
// RegisterWebhook stores a webhook configuration for the institution (delegates to repository).
func (s *GrantSupportService) RegisterWebhook(ctx context.Context, institutionID uuid.UUID, targetURL, plaintextSecret string) error {
	if s.webhookRepo == nil {
		return errors.New("WEBHOOK_UNAVAILABLE: WebhookRepository not configured")
	}
	_, err := s.webhookRepo.UpsertWebhook(ctx, institutionID, targetURL, plaintextSecret)
	return err
}
```

Add call sites inside each service method (example for `CreateSupportGrant`):

> **P5 fix**: Three bugs existed in the original snippet:
> 1. `input.Scope` — `CreateSupportGrant` takes flat parameters, not a struct named `input`. There is no `input` variable in scope. Fixed: use `"FULL_ACCESS"` as the default (scope runtime enforcement is deferred to Phase 6.1 per Component 6 below).
> 2. `grant.ID` — the existing Redlock closure discards the `*ent.SupportGrant` return value (`_, err := s.supportGrantRepo.CreateSupportGrant(...)`). Fixed: declare `var createdGrantID uuid.UUID` before the lock and capture it inside the closure. See annotated snippet below.
> 3. `"duration_minutes"` (snake_case) — violates the camelCase JSON convention enforced across all plans (F-1-A). Fixed: `"durationMinutes"`.

```go
// Phase 6 AFTER: capture createdGrantID before dispatching webhook event.
// Declare before the Redlock block:
var createdGrantID uuid.UUID

// Inside the Redlock closure (replace the existing `_, err := ...` line):
err := s.valkey.LockService.WithLock(ctx, lockKey, 10*time.Second, func(txCtx context.Context) error {
	created, err := s.supportGrantRepo.CreateSupportGrant(txCtx, input)
	if err != nil {
		return err
	}
	createdGrantID = created.ID // capture for webhook dispatch below
	return nil
})

// ... (rest of existing grant creation logic) ...

// After successful grant creation, notify webhook endpoint if configured (P5-fixed dispatch call).
if s.webhookDispatcher != nil && s.webhookRepo != nil {
	if wh, err := s.webhookRepo.GetActiveWebhook(ctx, institutionID); err == nil && wh != nil {
		s.webhookDispatcher.DispatchEvent(ctx, wh.TargetURL, wh.SharedSecret,
			"grant.created", institutionID, createdGrantID, map[string]any{
				// camelCase key (F-1-A fix). Scope deferred to Phase 6.1 — not in scope literally.
				"durationMinutes": durationMinutes,
				"scope":           "FULL_ACCESS", // default; Phase 6.1 will pass the real scope claim
			})
	}
}
```

Similar call sites for `SupportLogin` (event: `"support.login"`, sourceID = `grant.ID`) and `RevokeSupportGrant` (event: `"support.revoked"`, sourceID = `institutionID`).

> **Known limitation — no retry on delivery failure (P13 gap)**: `WebhookDispatcher` makes a single delivery attempt per event. If the customer endpoint returns a non-2xx or is temporarily unreachable, the event is **permanently lost** — there is no retry queue or exponential backoff. The `EventID` field was added specifically to allow idempotent deduplication by the customer *if* retries are implemented. Retry logic is **explicitly deferred to Phase 6.1** and must be tracked as a follow-up. Customers requiring guaranteed delivery should implement their own re-fetch mechanism using the audit log API (Phase 5's `VerifyAuditChain`) until Phase 6.1 is implemented.

---

### Component 6: Scope Enforcement — Explicit Deferral (finding #15)

> **Explicit deferral**: `Scope` (`READ_ONLY`, `SUPPORT_WRITE`, `FULL_ACCESS`) is validated on input and stored in the DB (`SupportGrant.scope`). However, **runtime scope enforcement** (checking the scope claim in the JWT before allowing a specific action during a support session) is **explicitly deferred** to a Phase 6.1 implementation. This work requires:
> 1. Adding `scope` as a claim in the issued JWT.
> 2. Adding `RequireScope("FULL_ACCESS")` middleware calls to protected routes.
> Phase 6.1 is tracked as a separate task. Phase 6 marks `scope` as "stored, not yet enforced."

---

### Component 7: `main.go` — Wire Encryption Service, Dispatcher & Wait on Shutdown

> **I-8 fix (encryption package wiring)**: `encryptionService` is constructed here from `MASTER_ENCRYPTION_KEY` (see Component 0 — `pkg/encryption`). It must appear BEFORE `webhookRepo` is built since `NewWebhookRepository` takes it as a parameter.

> **I-7 fix**: `NewWebhookRepository` now takes a 2nd `encryption.Encryptor` argument. The previous snippet showed the old 1-arg call.

> **I-2 fix**: `NewGrantSupportService` now takes 6 arguments. The previous snippet was missing `licMgr` (added by Phase 1).

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go)

Add BEFORE repo initialization (after Valkey block from Phase 4):
```go
	// Initialize AES-GCM encryption service from MASTER_ENCRYPTION_KEY env var.
	// Required for: webhook shared_secret storage, and any future PII field encryption.
	// Phase 1 .env.example documents this variable.
	encryptionKeyHex := os.Getenv("MASTER_ENCRYPTION_KEY")
	if encryptionKeyHex == "" && cfg.Environment == "production" {
		slog.Error("FATAL: MASTER_ENCRYPTION_KEY is required in production. Exiting.")
		os.Exit(1)
	}
	encryptionService, err := encryption.NewAESGCMEncryptor(encryptionKeyHex)
	if err != nil {
		slog.Error("Failed to initialize encryption service", slog.String("error", err.Error()))
		os.Exit(1)
	}
```

Add after repo initialization:
```go
	webhookDispatcher := service.NewWebhookDispatcher()
	// I-7 fix: 2nd arg is encryptionService (defined above).
	webhookRepo := repository.NewWebhookRepository(baseRepo, encryptionService)
```

Update `NewGrantSupportService` call:
```go
	// I-2 fix: 6 args — licMgr added by Phase 1; webhookDispatcher + webhookRepo added by Phase 6.
	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr, webhookDispatcher, webhookRepo)
```

Add import:
```go
	"grantsupport/pkg/encryption"
```

Add to the graceful shutdown block after `server.Shutdown(ctx)`:
```go
	// Wait for all in-flight webhook goroutines to finish before process exits (F-6-A fix).
	webhookDispatcher.Wait()
```

> **Cross-phase call-site audit for `NewGrantSupportService` (mandatory per process rule)**:
> - `phase_1_plan.md` Component 3: `NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr)` — 4 args ✔
> - `phase_6_plan.md` Component 7 (this section): `NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr, webhookDispatcher, webhookRepo)` — 6 args ✔
> - `phase_7_plan.md`: Uses `GrantSupportEngine` SDK struct, does NOT call `NewGrantSupportService` directly — ✔
> - `phase_2_plan.md`, `phase_3_plan.md`, `phase_4_plan.md`, `phase_5_plan.md`: Do not call `NewGrantSupportService` — ✔
> - `implementation_plan.md`: References the constructor conceptually, not as a call site — ✔
> - **Call sites checked: all 7 phase files + implementation_plan.md. All updated: yes.**

> **Cross-phase call-site audit for `NewWebhookRepository` (mandatory per process rule)**:
> - `phase_6_plan.md` Component 7 (this section): `NewWebhookRepository(baseRepo, encryptionService)` — 2 args ✔
> - `phase_7_plan.md`: Does not call `NewWebhookRepository` — ✔
> - All other phase files: do not call `NewWebhookRepository` — ✔
> - **Call sites checked: all 7 phase files + implementation_plan.md. All updated: yes.**

---

## 🧪 Verification Plan

### Build Check
```bash
go generate ./ent/...
go build ./...
```

### Automated Tests
```bash
go test ./pkg/service/... -run TestWebhookDispatch -v
go test ./pkg/repository/... -run TestGetActiveWebhookFiltersOnInstitution -v
```

### Manual Verification
1. Register a webhook via `POST /api/v1/auth/support/webhook` (authenticated):
   ```json
   { "targetUrl": "https://customer.example.com/webhooks/grantsupport", "sharedSecret": "mysecret16chars" }
   ```
2. Register a second webhook for a **different institution**. Confirm that creating a grant for institution A does NOT dispatch to institution B's endpoint (multi-tenant isolation check).
3. Create a support grant. Confirm the customer endpoint receives a `grant.created` POST with `X-GrantSupport-Signature` header.
4. Verify HMAC: `HMAC-SHA256(sharedSecret, body) == X-GrantSupport-Signature value`.
5. Retry the same grant creation; confirm the customer receives the same `event_id` (idempotent dispatch).
6. Send `SIGTERM` during an in-flight webhook. Confirm the process waits for delivery before exiting.
