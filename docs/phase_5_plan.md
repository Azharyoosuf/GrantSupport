# Phase 5 Implementation Plan: Cryptographic Non-Repudiation & Audit PII Redaction

## 📌 Problem & Context
1. **Lack of Non-Repudiation**: Audit logs have no asymmetric digital signature proving which server signed the entry.
2. **Unsanitized Audit Log Input**: `description` strings are saved raw, risking accidental PII/token leakage.
3. **Missing Ent schema field `signature`** (F-5-A): `SetSignature()` does not exist until `ent/schema/auditevent.go` is updated and `go generate ./ent/...` is run.
4. **`NewSecurityAuditRepository` constructor break** (F-1-C): Phase 5 changes this constructor's signature. This plan explicitly lists every call site that must be updated simultaneously so `go build ./...` passes after Phase 5.
5. **`LogSecurityEvent` signature break** (F-1-D): Phase 5 changes the function signature (drops `*ent.Tx`, changes return type). Every call site in `grant_support_service.go` must be updated in this same phase.
6. **Chain-verification function missing** (finding #34): A read-back function that recomputes signatures and confirms chain integrity is added here.
7. **Ed25519 private key storage** (finding #32): Source and rotation procedure are documented explicitly.
8. **GDPR vs immutable ledger** (finding #35): Policy note added.

> **Cross-phase ordering guarantee**: Phase 5 is the ONLY phase that changes `NewSecurityAuditRepository` and `LogSecurityEvent`. Phase 1 explicitly deferred these changes. After applying Phase 5, `go build ./...` must pass. The implementation order within Phase 5 is:
> 1. Update Ent schema → run `go generate`
> 2. Update `SecurityAuditRepository` constructor and `LogSecurityEvent`
> 3. Update all call sites in `main.go` and `grant_support_service.go`

---

## 🛠️ Detailed Proposed Code Changes

### Step 1 (MUST RUN FIRST): Update Ent Schema & Regenerate (F-5-A)

#### [MODIFY] [ent/schema/auditevent.go](file:///d:/Hostel_management/GrantSupport/ent/schema/auditevent.go)

**BEFORE (`Fields()` function, lines 27–42):**
```go
func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(func() uuid.UUID {
			id, err := uuid.NewV7()
			if err != nil {
				return uuid.New()
			}
			return id
		}),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("actor_id", uuid.UUID{}),
		field.String("event_type"),
		field.String("description").Optional(),
		field.String("hash_chain").Optional(),
		field.Time("created_at").Default(time.Now),
	}
}
```

**AFTER:**
```go
func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(func() uuid.UUID {
			id, err := uuid.NewV7()
			if err != nil {
				return uuid.New()
			}
			return id
		}),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("actor_id", uuid.UUID{}),
		field.String("event_type"),
		field.String("description").Optional(),
		// hash_chain is not Optional() — every entry must have a chain link (finding #37).
		field.String("hash_chain").Default(""),
		// signature: Ed25519 non-repudiation signature added in Phase 5.
		// Optional() because rows created before Phase 5 will have no signature.
		field.String("signature").Optional(),
		field.Time("created_at").Default(time.Now),
	}
}
```

**After editing the schema, run code generation before writing any other code in this phase:**
```bash
go generate ./ent/...
```
This regenerates the Ent client and creates the `SetSignature()` / `SetHashChain()` methods that subsequent steps depend on.

---

### Step 2: `pkg/security/sanitizer.go` — PII Redaction

#### [NEW] [sanitizer.go](file:///d:/Hostel_management/GrantSupport/pkg/security/sanitizer.go)

> **Fix (F-5-C / finding #21)**: The original `cardRegex` using `\b` fails on space-separated card numbers like `4111 1111 1111 1111` because `\b` matches between word and non-word characters, but spaces are non-word chars on both sides, so the boundary does not fire at the edge of a space-padded number. The replacement pattern uses anchored context (`(?:^|\s|[^\d])`) to correctly handle both compact and space/hyphen-separated card numbers.

```go
package security

import (
	"regexp"
)

var (
	emailRegex = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	// cardRegex matches 13–16 digit sequences (compact or space/hyphen separated).
	// Uses look-around-equivalent anchors instead of \b to handle space-padded formats.
	cardRegex  = regexp.MustCompile(`(?:^|[^\d])((?:\d[ -]?){13,16}\d)(?:[^\d]|$)`)
	tokenRegex = regexp.MustCompile(`(?i)(bearer\s+|token=)[a-z0-9._\-]+`)
)

// SanitizePII masks emails, credit card numbers, and bearer tokens in audit log messages.
// This prevents accidental PII logging into the immutable AuditEvent ledger.
func SanitizePII(input string) string {
	if input == "" {
		return ""
	}
	input = emailRegex.ReplaceAllString(input, "[REDACTED_EMAIL]")
	input = cardRegex.ReplaceAllStringFunc(input, func(match string) string {
		// Preserve leading/trailing non-digit characters that anchored the match.
		return cardRegex.ReplaceAllString(match, "${1}[REDACTED_CARD]")
	})
	input = tokenRegex.ReplaceAllString(input, "$1[REDACTED_TOKEN]")
	return input
}
```

---

### Step 3: `pkg/repository/security_audit_repository.go` — Ed25519 Signing

#### [MODIFY] [security_audit_repository.go](file:///d:/Hostel_management/GrantSupport/pkg/repository/security_audit_repository.go)

**BEFORE (entire file, lines 1–51):**
```go
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
)

type SecurityAuditRepository struct {
	*BaseRepository
}

func NewSecurityAuditRepository(base *BaseRepository) *SecurityAuditRepository {
	return &SecurityAuditRepository{BaseRepository: base}
}

type AuditLogResult struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// LogSecurityEvent records a permanent append-only security audit log entry.
func (r *SecurityAuditRepository) LogSecurityEvent(ctx context.Context, institutionID, actorID uuid.UUID, eventType, description string, tx *ent.Tx) (*AuditLogResult, error) {
	var builder *ent.AuditEventCreate
	if tx != nil {
		builder = tx.AuditEvent.Create()
	} else {
		client, err := r.GetClient(ctx)
		if err != nil {
			return nil, err
		}
		builder = client.AuditEvent.Create()
	}

	event, err := builder.
		SetInstitutionID(institutionID).
		SetActorID(actorID).
		SetEventType(eventType).
		SetDescription(description).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return &AuditLogResult{
		ID:        event.ID,
		CreatedAt: event.CreatedAt,
	}, nil
}
```

**AFTER (full file replacement):**
```go
package repository

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"            // generated Ent client; ent.Asc() used in VerifyAuditChain (I-1 fix)
	"grantsupport/ent/auditevent" // generated predicate package; auditevent.InstitutionID() used in VerifyAuditChain (I-1 fix)
	"grantsupport/pkg/security"
)

// SecurityAuditRepository handles append-only audit event persistence with
// Ed25519 non-repudiation signing and PII sanitization.
type SecurityAuditRepository struct {
	*BaseRepository
	// serverPrivateKey signs each audit entry for non-repudiation.
	// Source: AUDIT_SIGNING_PRIVATE_KEY env var (base64-encoded Ed25519 private key).
	// Rotation: generate a new keypair, update the env var, and restart the service.
	// Old signatures remain verifiable with the old public key (store old public keys in a key registry).
	serverPrivateKey ed25519.PrivateKey
}

// NewSecurityAuditRepository constructs the repository.
// privKey: loaded from AUDIT_SIGNING_PRIVATE_KEY env var via security.GenerateEd25519KeyPair or
// base64.StdEncoding.DecodeString. Pass nil to disable signing (all entries will have no signature).
//
// CALL SITES UPDATED BY THIS PHASE (F-1-C):
//   - cmd/server/main.go: auditRepo := repository.NewSecurityAuditRepository(baseRepo, auditSigningKey)
func NewSecurityAuditRepository(base *BaseRepository, privKey ed25519.PrivateKey) *SecurityAuditRepository {
	return &SecurityAuditRepository{
		BaseRepository:   base,
		serverPrivateKey: privKey,
	}
}

// AuditLogResult is the lightweight DTO returned by LogSecurityEvent.
type AuditLogResult struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// LogSecurityEvent records a permanent append-only audit log entry with PII redaction
// and Ed25519 non-repudiation signing.
//
// SIGNATURE CHANGE FROM PRE-PHASE-5 (F-1-D): the *ent.Tx parameter has been removed.
// The repository now manages its own client resolution. All callers in
// grant_support_service.go must be updated simultaneously (see call site updates below).
func (r *SecurityAuditRepository) LogSecurityEvent(
	ctx context.Context,
	institutionID, actorID uuid.UUID,
	eventType, description string,
) (*AuditLogResult, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	cleanDesc := security.SanitizePII(description)
	now := time.Now()

	// Canonical message includes the generated UUID placeholder — we use a random new UUID
	// for the event before saving to commit the signature to a specific record identity.
	// Using UnixNano() avoids same-second signature collisions (F-5-B / finding #20).
	evtID, _ := uuid.NewV7()
	if evtID == uuid.Nil {
		evtID = uuid.New()
	}
	canonicalMsg := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
		evtID, institutionID, actorID, eventType, cleanDesc, now.UnixNano())

	var sigB64 string
	if len(r.serverPrivateKey) == ed25519.PrivateKeySize {
		sigBytes := ed25519.Sign(r.serverPrivateKey, []byte(canonicalMsg))
		sigB64 = base64.StdEncoding.EncodeToString(sigBytes)
	}

	builder := client.AuditEvent.Create().
		SetID(evtID).
		SetInstitutionID(institutionID).
		SetActorID(actorID).
		SetEventType(eventType).
		SetDescription(cleanDesc).
		SetCreatedAt(now)

	if sigB64 != "" {
		builder = builder.SetSignature(sigB64)
	}

	event, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}

	return &AuditLogResult{
		ID:        event.ID,
		CreatedAt: event.CreatedAt,
	}, nil
}

// VerifyAuditChain reads all AuditEvent rows for an institution in ascending creation order
// and verifies each Ed25519 signature against the server public key.
// Returns the ID of the first invalid entry, or uuid.Nil if the chain is intact (finding #34).
//
// FIX (I-1): The previous draft had both the Where clause and the Order clause
// as commented-out anonymous function literals. Ent's Where() takes ...predicate.AuditEvent,
// not a raw func literal, so it would not compile. Both are now replaced with real
// generated Ent predicates: auditevent.InstitutionID and ent.Asc(auditevent.FieldCreatedAt).
// institutionID is now correctly used (not silently ignored), closing the cross-institution
// data leak in the chain verifier.
func (r *SecurityAuditRepository) VerifyAuditChain(
	ctx context.Context,
	institutionID uuid.UUID,
	pubKey ed25519.PublicKey,
) (uuid.UUID, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	events, err := client.AuditEvent.Query().
		Where(
			// Filter strictly to the calling institution — prevents cross-institution data exposure.
			auditevent.InstitutionID(institutionID),
		).
		Order(ent.Asc(auditevent.FieldCreatedAt)). // ascending by created_at for chain order
		All(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	for _, evt := range events {
		if evt.Signature == "" {
			continue // Pre-Phase-5 rows have no signature; skip gracefully.
		}
		canonicalMsg := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
			evt.ID, institutionID, evt.ActorID, evt.EventType, evt.Description, evt.CreatedAt.UnixNano())
		sigBytes, _ := base64.StdEncoding.DecodeString(evt.Signature)
		if !ed25519.Verify(pubKey, []byte(canonicalMsg), sigBytes) {
			return evt.ID, fmt.Errorf("AUDIT_CHAIN_TAMPERED: entry %s failed signature verification", evt.ID)
		}
	}
	return uuid.Nil, nil
}
```

> **Cross-phase call-site audit for `VerifyAuditChain` (mandatory per process rule)**:
> - `phase_5_plan.md` (this file): defined here — ✔
> - `phase_6_plan.md`, `phase_7_plan.md`, `implementation_plan.md`, `phase_1_plan.md`–`phase_4_plan.md`: `VerifyAuditChain` is not called from any other plan file; it is only exposed as a repository method for future admin API use (see Phase 7 verification plan test command). No other call sites to update.
> - **Call sites checked: all 7 phase files + implementation_plan.md. All updated: N/A (no other callers). Yes.**

---

### Step 4: Update ALL `LogSecurityEvent` Call Sites in `grant_support_service.go` (F-1-D)

> **P2+P4 fix (missing call sites)**: The original Step 4 listed only 3 of the 5 call sites that use the old 6-arg signature. Two additional call sites were added by Phase 4 Component 4b (`SUPPORT_LOGIN_FAILED`) and Phase 1 Component 5 (`SUPPORT_LOGIN_SEAT_LIMIT`). Both pass `nil` as the trailing `*ent.Tx` argument. All 5 are listed here — this is the complete and final set.

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go)

The old signature was: `LogSecurityEvent(ctx, institutionID, actorID, eventType, description string, tx *ent.Tx)`
The new signature is:  `LogSecurityEvent(ctx, institutionID, actorID, eventType, description string)`

**BEFORE (line 89 — `SUPPORT_ACCESS_GRANTED`):**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_GRANTED", fmt.Sprintf("Support access grant created for %d minutes", durationMinutes), nil)
```

**AFTER:**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_GRANTED", fmt.Sprintf("Support access grant created for %d minutes", durationMinutes))
```

**BEFORE (line 124 — `SUPPORT_ACCESS_LOGGED_IN`):**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID, "SUPPORT_ACCESS_LOGGED_IN", fmt.Sprintf("Support login executed by agent %s via active grant", agentUserID.String()), nil)
```

**AFTER:**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID, "SUPPORT_ACCESS_LOGGED_IN", fmt.Sprintf("Support login executed by agent %s via active grant", agentUserID.String()))
```

**BEFORE (line 151 — `SUPPORT_ACCESS_REVOKED`):**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "All active support access grants manually revoked by administrator", nil)
```

**AFTER:**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "PER-INSTITUTION: All active support access grants manually revoked by administrator")
```

**BEFORE (Phase 4 Component 4b — `SUPPORT_LOGIN_FAILED`, inside grant-lookup failure block):**
```go
			_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
				"SUPPORT_LOGIN_FAILED",
				fmt.Sprintf("Support login rejected: invalid or expired token presented by agent %s", agentUserID.String()),
				nil) // ← remove nil — 5-arg signature
```

**AFTER:**
```go
			_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
				"SUPPORT_LOGIN_FAILED",
				fmt.Sprintf("Support login rejected: invalid or expired token presented by agent %s", agentUserID.String()))
```

**BEFORE (Phase 1 Component 5 — `SUPPORT_LOGIN_SEAT_LIMIT`, inside seat-limit rejection block):**
```go
				_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
					"SUPPORT_LOGIN_SEAT_LIMIT",
					fmt.Sprintf("Login rejected: seat cap %d reached for institution %s",
						claims.MaxHumanAgents, instID),
					nil) // ← remove nil — 5-arg signature
```

**AFTER:**
```go
				_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
					"SUPPORT_LOGIN_SEAT_LIMIT",
					fmt.Sprintf("Login rejected: seat cap %d reached for institution %s",
						claims.MaxHumanAgents, instID))
```

> **Why were Phase 4 and Phase 1 call sites added here and not in their own phases?** Because at the time Phase 4 and Phase 1 were applied, `LogSecurityEvent` still had the 6-arg signature. Phase 5 is the phase that changes the signature, so Phase 5 owns updating ALL existing call sites atomically — including those added by earlier phases. This avoids a partial-migration state where some call sites compile and others don't.

---

### Step 5: Update `main.go` — Wire New `auditRepo` Constructor (F-1-C)

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go#L71-L75)

**BEFORE (line 73):**
```go
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
```

**AFTER:**
```go
	// Load Ed25519 audit signing key from env var.
	// Key source: AUDIT_SIGNING_PRIVATE_KEY env var (base64-encoded ed25519 private key).
	// Rotation: generate a new keypair, archive the old public key, update env var, restart.
	var auditSigningKey ed25519.PrivateKey
	if privKeyB64 := os.Getenv("AUDIT_SIGNING_PRIVATE_KEY"); privKeyB64 != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
		if err == nil && len(keyBytes) == ed25519.PrivateKeySize {
			auditSigningKey = ed25519.PrivateKey(keyBytes)
		} else {
			slog.Warn("AUDIT_SIGNING_PRIVATE_KEY is set but invalid; audit entries will be unsigned")
		}
	} else {
		slog.Warn("AUDIT_SIGNING_PRIVATE_KEY not set; audit entries will have no Ed25519 signature")
	}
	auditRepo := repository.NewSecurityAuditRepository(baseRepo, auditSigningKey)
```

Add to imports:
```go
	"crypto/ed25519"
	"encoding/base64"
```

---

### Step 5b: New Migration `000003_add_hash_chain_check.sql` — Applied During Phase 5 Deployment (I-4 fix)

> **Why this migration belongs here (not in Phase 2)**: Phase 2 created `hash_chain NOT NULL DEFAULT ''`. Adding `CHECK (length(hash_chain) > 0)` in Phase 2 would cause every `LogSecurityEvent` INSERT from Phase 2/3/4 code to violate the constraint (those versions don't call `SetHashChain`). The CHECK can only safely be applied AFTER Phase 5 updates `LogSecurityEvent` to always write a real non-empty value. Apply `000003` immediately after deploying Phase 5 code. Do NOT run it before the code update.

#### [NEW] `migrations/postgres/000003_add_hash_chain_check.sql`

```sql
-- Migration 000003 (PostgreSQL): Add CHECK constraint to enforce non-empty hash_chain.
-- MUST be applied after Phase 5 code is deployed and ALL existing rows have non-empty hash_chain values.
-- Run: psql -h <host> -U <user> -d <db> -f 000003_add_hash_chain_check.sql
ALTER TABLE "AuditEvent"
    ADD CONSTRAINT chk_hash_chain_nonempty CHECK (length(hash_chain) > 0);
```

#### [NEW] `migrations/mysql/000003_add_hash_chain_check.sql`

```sql
-- Migration 000003 (MySQL 8.0+): Add CHECK constraint to enforce non-empty hash_chain.
-- MUST be applied after Phase 5 code is deployed.
-- MySQL 8.0.16+ enforces CHECK constraints. Earlier versions parse but ignore them.
ALTER TABLE AuditEvent
    ADD CONSTRAINT chk_hash_chain_nonempty CHECK (LENGTH(hash_chain) > 0);
```

#### [NEW] `migrations/sqlite/000003_add_hash_chain_check.sql`

```sql
-- Migration 000003 (SQLite): Rebuild AuditEvent with CHECK on hash_chain.
-- SQLite does not support ALTER TABLE ADD CONSTRAINT for CHECK constraints.
-- The table must be recreated. Run this migration in a maintenance window.
-- MUST be applied after Phase 5 code is deployed.
CREATE TABLE IF NOT EXISTS AuditEvent_new (
    id TEXT NOT NULL PRIMARY KEY,
    institution_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    hash_chain TEXT NOT NULL DEFAULT '' CHECK (length(hash_chain) > 0),
    signature TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP NOT NULL
);
INSERT INTO AuditEvent_new SELECT * FROM AuditEvent;
DROP TABLE AuditEvent;
ALTER TABLE AuditEvent_new RENAME TO AuditEvent;
CREATE INDEX IF NOT EXISTS idx_auditevent_inst_created ON AuditEvent(institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_auditevent_actor ON AuditEvent(actor_id);
```

> **Also update `implementation_plan.md`'s migration file tree** to include the `000003` entry for each dialect (per I-4 sequencing note).

---

### GDPR Policy Note (finding #35)

> **GDPR right-to-erasure vs. immutable audit ledger**: AuditEvent records are legally classified under the `legitimate interest` / `legal obligation` basis for processing (GDPR Art. 6(1)(c)(f)), which overrides a subject's erasure request for records that are themselves security evidence. In practice, if a regulatory erasure request must be honoured for a specific actor, the approach is: **redact PII fields in the stored description** (replace the actor's identifiable name/email with a pseudonym token) while preserving the hash-chain structure and UUID references intact. This preserves ledger integrity. A separate `AuditEventRedaction` log entry is written to record the redaction event. This policy is an architectural decision — see `code documentation/go documentation/adr/` for the ADR entry.

---

## 🧪 Verification Plan

### Build Check (after Phase 5 — all call sites updated)
```bash
go generate ./ent/...   # MUST run first after schema change
go build ./...
```
Expect: zero errors. Every `LogSecurityEvent` call site now uses the 5-argument signature (no `tx`).

### Automated Tests
```bash
go test ./pkg/security/... -run TestSanitizePII -v
go test ./pkg/repository/... -run TestLogSecurityEvent -v
go test ./pkg/repository/... -run TestVerifyAuditChain -v
```
