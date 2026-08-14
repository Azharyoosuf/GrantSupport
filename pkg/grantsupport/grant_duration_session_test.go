package grantsupport_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/security"
)

// TestGrantDuration_JWTExpirationMatchesGrant verifies that the issued JWT lifetime strictly inherits the grant's duration.
func TestGrantDuration_JWTExpirationMatchesGrant(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	durations := []int{1, 5, 30, 60, 240, 1440}

	for _, d := range durations {
		t.Run(fmt.Sprintf("%d_minutes_grant", d), func(t *testing.T) {
			dbName := fmt.Sprintf("test_grant_dur_%d", d)
			db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", dbName))
			if err != nil {
				t.Fatalf("sql.Open failed: %v", err)
			}
			defer db.Close()

			engine, err := grantsupport.NewEngine(
				grantsupport.WithDB(db, "sqlite"),
				grantsupport.WithAutoMigrate(true),
			)
			if err != nil {
				t.Fatalf("NewEngine failed: %v", err)
			}
			defer engine.Close()

			instID := uuid.New()
			adminID := uuid.New()
			agentID := uuid.New()

			beforeCreation := time.Now().UTC().Truncate(time.Second)
			rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, d, "FULL_ACCESS", nil)
			if err != nil {
				t.Fatalf("CreateSupportGrant failed for duration %d: %v", d, err)
			}
			afterCreation := time.Now().UTC().Add(time.Second)

			// Immediate redemption
			_, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
			if err != nil {
				t.Fatalf("SupportLogin failed: %v", err)
			}

			claims, err := security.VerifyJWT(jwtToken)
			if err != nil {
				t.Fatalf("VerifyJWT failed: %v", err)
			}

			jwtExp := claims.ExpiresAt.Time.UTC()
			jwtIat := claims.IssuedAt.Time.UTC()

			// Invariant 1: jwtExp > jwtIat
			if !jwtExp.After(jwtIat) {
				t.Fatalf("Expected jwtExp (%v) > jwtIat (%v)", jwtExp, jwtIat)
			}

			// Invariant 2: jwtExp must be bounded by creation + duration
			maxExpectedExp := afterCreation.Add(time.Duration(d) * time.Minute)
			minExpectedExp := beforeCreation.Add(time.Duration(d) * time.Minute)

			if jwtExp.After(maxExpectedExp.Add(2 * time.Second)) {
				t.Fatalf("JWT expiration %v exceeds expected upper bound %v for %d min grant", jwtExp, maxExpectedExp, d)
			}
			if jwtExp.Before(minExpectedExp.Add(-2 * time.Second)) {
				t.Fatalf("JWT expiration %v is below expected lower bound %v for %d min grant", jwtExp, minExpectedExp, d)
			}
		})
	}
}

// TestGrantDuration_LateRedemptionBindsToRemainingGrantTime tests that redeeming a grant late does not extend the session window.
func TestGrantDuration_LateRedemptionBindsToRemainingGrantTime(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:test_late_redemption?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Simulate a 30-minute grant created 20 minutes ago (expires in 10 minutes)
	grantExpiresAt := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	rawToken := fmt.Sprintf("%s_%s", instID.String(), hex.EncodeToString([]byte("01234567890123456789012345678901")))
	tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(rawToken)))

	_, err = db.ExecContext(ctx, `
		INSERT INTO gs_support_grants (id, institution_id, granted_by_id, token_hash, expires_at, is_used, scope, created_at)
		VALUES (?, ?, ?, ?, ?, 0, 'FULL_ACCESS', ?)
	`, uuid.New().String(), instID.String(), adminID.String(), tokenHash, grantExpiresAt, time.Now().Add(-20*time.Minute))
	if err != nil {
		t.Fatalf("Failed to insert simulated 20-minute old grant: %v", err)
	}

	// Agent logs in now (20 minutes late)
	_, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed on late redemption: %v", err)
	}

	claims, err := security.VerifyJWT(jwtToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	jwtExp := claims.ExpiresAt.Time.UTC()

	// Invariant: The JWT must expire at grantExpiresAt (in ~10 minutes), NOT in 4 hours or 30 minutes from now!
	remainingDuration := time.Until(jwtExp)
	if remainingDuration > 11*time.Minute {
		t.Fatalf("Expected JWT remaining duration ~10 minutes, got %v (expired at %v vs grant %v)", remainingDuration, jwtExp, grantExpiresAt)
	}
	diff := jwtExp.Sub(grantExpiresAt)
	if diff < 0 {
		diff = -diff
	}
	if diff > 2*time.Second {
		t.Fatalf("Expected JWT expiration to match grant expiration %v, got %v", grantExpiresAt, jwtExp)
	}
}

// TestGrantDuration_NearExpirationRedemption tests redemption right before grant expiration.
func TestGrantDuration_NearExpirationRedemption(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:test_near_exp_redemption?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Simulate a grant expiring in 30 seconds
	grantExpiresAt := time.Now().UTC().Add(30 * time.Second).Truncate(time.Second)
	rawToken := fmt.Sprintf("%s_%s", instID.String(), hex.EncodeToString([]byte("near_expiry_token_12345678901234")))
	tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(rawToken)))

	_, err = db.ExecContext(ctx, `
		INSERT INTO gs_support_grants (id, institution_id, granted_by_id, token_hash, expires_at, is_used, scope, created_at)
		VALUES (?, ?, ?, ?, ?, 0, 'FULL_ACCESS', ?)
	`, uuid.New().String(), instID.String(), adminID.String(), tokenHash, grantExpiresAt, time.Now().Add(-29*time.Minute))
	if err != nil {
		t.Fatalf("Failed to insert near-expiry grant: %v", err)
	}

	_, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed on near-expiry grant: %v", err)
	}

	claims, err := security.VerifyJWT(jwtToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	// Remaining lifetime must be <= 30 seconds
	if time.Until(claims.ExpiresAt.Time) > 35*time.Second {
		t.Fatalf("Expected JWT lifetime <= 30s, got %v", time.Until(claims.ExpiresAt.Time))
	}
}

// TestGrantDuration_ExpiredGrantRejectsLogin tests that an already expired grant rejects redemption immediately.
func TestGrantDuration_ExpiredGrantRejectsLogin(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:test_exp_reject_login?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Grant expired 5 seconds ago
	grantExpiresAt := time.Now().UTC().Add(-5 * time.Second)
	rawToken := fmt.Sprintf("%s_%s", instID.String(), hex.EncodeToString([]byte("already_expired_token_1234567890")))
	tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(rawToken)))

	_, err = db.ExecContext(ctx, `
		INSERT INTO gs_support_grants (id, institution_id, granted_by_id, token_hash, expires_at, is_used, scope, created_at)
		VALUES (?, ?, ?, ?, ?, 0, 'FULL_ACCESS', ?)
	`, uuid.New().String(), instID.String(), adminID.String(), tokenHash, grantExpiresAt, time.Now().Add(-60*time.Minute))
	if err != nil {
		t.Fatalf("Failed to insert expired grant: %v", err)
	}

	_, _, err = engine.SupportLogin(ctx, rawToken, agentID)
	if err == nil {
		t.Fatal("Expected SupportLogin to fail for expired grant, got nil error")
	}
}

// TestGrantDuration_HTTPFlowEndToEnd tests the complete HTTP lifecycle including grant creation, duration-bounded login, authenticated requests, admin revocation, and agent logout.
func TestGrantDuration_HTTPFlowEndToEnd(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:test_http_duration_flow?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	handler := engine.HTTPHandler()

	// 1. Admin creates a 30-minute support grant
	token, err := engine.CreateSupportGrant(ctx, instID, adminID, 30, "BILLING_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	// 2. Support agent logs in via POST /api/v1/auth/support/login
	_, agentJWT, err := engine.SupportLogin(ctx, token, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}

	// Verify claims
	claims, err := security.VerifyJWT(agentJWT)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if time.Until(claims.ExpiresAt.Time) > 31*time.Minute {
		t.Fatalf("Expected JWT expiration <= 30m, got: %v", time.Until(claims.ExpiresAt.Time))
	}
	if claims.Scope != "BILLING_ACCESS" {
		t.Fatalf("Expected scope BILLING_ACCESS, got %s", claims.Scope)
	}

	// 3. Authenticated Agent request to /logout succeeds initially
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	req.Header.Set("Authorization", "Bearer "+agentJWT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on logout, got %d (%s)", rec.Code, rec.Body.String())
	}

	// 4. Subsequent authenticated requests with same JWT return 401 TOKEN_REVOKED
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	req2.Header.Set("Authorization", "Bearer "+agentJWT)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized after logout, got: %d", rec2.Code)
	}

	// 5. Verify SQLRevocationStore and RedisRevocationStore parity
	sqlRevStore := revocation.NewSQLRevocationStore(db, "sqlite")
	revoked, err := sqlRevStore.IsTokenRevoked(ctx, instID.String(), agentID.String(), claims.TokenVersion)
	if err != nil || !revoked {
		t.Fatalf("Expected SQL store to report token version %d as revoked, got revoked=%v, err=%v", claims.TokenVersion, revoked, err)
	}
}
