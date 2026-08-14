package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

// mockFailingRateLimiter simulates a rate limiter backend outage
type mockFailingRateLimiter struct{}

func (m *mockFailingRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	return false, errors.New("valkey connection refused")
}

// mockFailingRevocationStore simulates a revocation store backend outage
type mockFailingRevocationStore struct{}

func (m *mockFailingRevocationStore) IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error) {
	return false, errors.New("database connection timeout")
}
func (m *mockFailingRevocationStore) RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error {
	return errors.New("database connection timeout")
}
func (m *mockFailingRevocationStore) GetUserTokenVersion(ctx context.Context, institutionID, userID string) (int, error) {
	return 0, errors.New("database connection timeout")
}

func parseProblemDetails(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/problem+json" {
		t.Fatalf("Expected Content-Type 'application/problem+json', got '%s'", contentType)
	}

	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to decode Problem Details JSON: %v, Body: %s", err, rec.Body.String())
	}
	return result
}

// TestErrorContract_MalformedJSON verifies that malformed JSON payloads return HTTP 400 INVALID_JSON.
func TestErrorContract_MalformedJSON(t *testing.T) {
	ctrl := controller.NewSupportGrantController(nil)
	handler := controller.CatchAsync(ctrl.SupportLogin)

	req := httptest.NewRequest("POST", "/api/v1/auth/support/login", bytes.NewBufferString("{invalid_json:true}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}

	pd := parseProblemDetails(t, rec)
	if pd["title"] != "INVALID_JSON" {
		t.Errorf("Expected title 'INVALID_JSON', got '%v'", pd["title"])
	}
}

// TestErrorContract_ValidationFailure verifies that missing or invalid fields return HTTP 400 VALIDATION_ERROR.
func TestErrorContract_ValidationFailure(t *testing.T) {
	ctrl := controller.NewSupportGrantController(nil)
	handler := controller.CatchAsync(ctrl.SupportLogin)

	// Missing agentId and empty token
	req := httptest.NewRequest("POST", "/api/v1/auth/support/login", bytes.NewBufferString(`{"token":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}

	pd := parseProblemDetails(t, rec)
	if pd["title"] != "VALIDATION_ERROR" {
		t.Errorf("Expected title 'VALIDATION_ERROR', got '%v'", pd["title"])
	}
	if !strings.Contains(rec.Body.String(), "failed validation rule") {
		t.Errorf("Expected validation detail message, got %s", rec.Body.String())
	}
}

// TestErrorContract_PayloadTooLarge verifies that request payloads > 1MB return HTTP 413 PAYLOAD_TOO_LARGE.
func TestErrorContract_PayloadTooLarge(t *testing.T) {
	ctrl := controller.NewSupportGrantController(nil)
	handler := controller.CatchAsync(ctrl.SupportLogin)

	// Create oversized payload (> 1MB) of valid JSON
	oversized := `{"token":"` + strings.Repeat("a", 1024*1024+100) + `"}`
	req := httptest.NewRequest("POST", "/api/v1/auth/support/login", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413 Request Entity Too Large, got %d", rec.Code)
	}

	pd := parseProblemDetails(t, rec)
	if pd["title"] != "PAYLOAD_TOO_LARGE" {
		t.Errorf("Expected title 'PAYLOAD_TOO_LARGE', got '%v'", pd["title"])
	}
}

// TestErrorContract_PanicRecoverySanitization verifies that unhandled panics in handlers return sanitized HTTP 500 without leaking stack traces.
func TestErrorContract_PanicRecoverySanitization(t *testing.T) {
	panickingHandler := controller.CatchAsync(func(w http.ResponseWriter, r *http.Request) error {
		panic("critical database driver memory corrupt: pointer 0xdeadbeef at table gs_support_grants")
	})

	req := httptest.NewRequest("GET", "/api/v1/test/panic", nil)
	rec := httptest.NewRecorder()

	panickingHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 Internal Server Error, got %d", rec.Code)
	}

	pd := parseProblemDetails(t, rec)
	if pd["title"] != "INTERNAL_SERVER_ERROR" {
		t.Errorf("Expected title 'INTERNAL_SERVER_ERROR', got '%v'", pd["title"])
	}

	// Verify no internal technical details or table names leaked
	bodyStr := rec.Body.String()
	if strings.Contains(bodyStr, "gs_support_grants") || strings.Contains(bodyStr, "0xdeadbeef") {
		t.Fatalf("Information disclosure violation: Internal panic message leaked to client: %s", bodyStr)
	}
}

// TestErrorContract_FailClosedRateLimiter verifies that a failing rate limiter rejects requests with HTTP 503 instead of allowing unthrottled access.
func TestErrorContract_FailClosedRateLimiter(t *testing.T) {
	failingLimiter := &mockFailingRateLimiter{}
	mw := middleware.RateLimitMiddleware(failingLimiter, 10, 60)

	nextCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("Security Violation: Next handler was called when rate limiter backend failed (failed open)")
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503 Service Unavailable, got %d", rec.Code)
	}

	pd := parseProblemDetails(t, rec)
	if pd["title"] != "RATE_LIMIT_UNAVAILABLE" {
		t.Errorf("Expected title 'RATE_LIMIT_UNAVAILABLE', got '%v'", pd["title"])
	}
}

// TestErrorContract_FailClosedRevocationStore verifies that a failing revocation store rejects requests with HTTP 503.
func TestErrorContract_FailClosedRevocationStore(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	instID := uuid.New().String()
	userID := uuid.New().String()
	tokenStr, err := security.GenerateJWTWithVersion(userID, instID, "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion failed: %v", err)
	}

	failingRevStore := &mockFailingRevocationStore{}
	mw := middleware.NewAuthMiddleware(failingRevStore)

	nextCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("Security Violation: Request succeeded when revocation store was unavailable (failed open)")
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503 Service Unavailable, got %d", rec.Code)
	}

	pd := parseProblemDetails(t, rec)
	if pd["title"] != "REVOCATION_CHECK_UNAVAILABLE" {
		t.Errorf("Expected title 'REVOCATION_CHECK_UNAVAILABLE', got '%v'", pd["title"])
	}
}

// TestErrorContract_RevokedSessionToken verifies that a revoked session token returns HTTP 401 TOKEN_REVOKED.
func TestErrorContract_RevokedSessionToken(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	instID := uuid.New().String()
	userID := uuid.New().String()
	tokenStr, _ := security.GenerateJWTWithVersion(userID, instID, "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)

	// Mock revocation store returning revoked = true
	revStore := &mockRevokedStore{isRevoked: true}
	mw := middleware.NewAuthMiddleware(revStore)

	req := httptest.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized, got %d", rec.Code)
	}

	pd := parseProblemDetails(t, rec)
	if pd["title"] != "TOKEN_REVOKED" {
		t.Errorf("Expected title 'TOKEN_REVOKED', got '%v'", pd["title"])
	}
}

type mockRevokedStore struct {
	isRevoked bool
}

func (m *mockRevokedStore) IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error) {
	return m.isRevoked, nil
}
func (m *mockRevokedStore) RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error {
	return nil
}
func (m *mockRevokedStore) GetUserTokenVersion(ctx context.Context, institutionID, userID string) (int, error) {
	return 2, nil
}

// TestErrorContract_MissingTenantContext verifies that protected endpoints without auth context return HTTP 401 UNAUTHORIZED.
func TestErrorContract_MissingTenantContext(t *testing.T) {
	ctrl := controller.NewSupportGrantController(nil)

	t.Run("GrantSupport without context", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/support/grant", bytes.NewBufferString(`{"durationMinutes":60}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		controller.CatchAsync(ctrl.GrantSupport).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Expected 401 Unauthorized, got %d", rec.Code)
		}
		pd := parseProblemDetails(t, rec)
		if pd["title"] != "UNAUTHORIZED" {
			t.Errorf("Expected title 'UNAUTHORIZED', got '%v'", pd["title"])
		}
	})

	t.Run("RevokeSupport without context", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/support/revoke", nil)
		rec := httptest.NewRecorder()

		controller.CatchAsync(ctrl.RevokeSupport).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Expected 401 Unauthorized, got %d", rec.Code)
		}
	})
}

// TestErrorContract_RBACForbidden verifies that authorized users with insufficient roles receive HTTP 403 FORBIDDEN.
func TestErrorContract_RBACForbidden(t *testing.T) {
	mw := middleware.RequireRoles("ADMINISTRATOR", "OWNER")

	req := httptest.NewRequest("POST", "/api/v1/admin/action", nil)
	// Inject tenant with READ_ONLY role
	ctx := pkgctx.WithTenant(req.Context(), &pkgctx.TenantData{
		InstitutionID: uuid.New(),
		UserID:        uuid.New(),
		Role:          "READ_ONLY",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden, got %d", rec.Code)
	}

	pd := parseProblemDetails(t, rec)
	if pd["title"] != "FORBIDDEN" {
		t.Errorf("Expected title 'FORBIDDEN', got '%v'", pd["title"])
	}
}

// TestErrorContract_SupportLoginInformationDisclosure verifies uniform 401 for invalid, malformed, or missing tokens.
func TestErrorContract_SupportLoginInformationDisclosure(t *testing.T) {
	// Create minimal service with nil repo to trigger invalid token format
	svc := service.NewGrantSupportService(nil, nil, nil)
	ctrl := controller.NewSupportGrantController(svc)
	handler := controller.CatchAsync(ctrl.SupportLogin)

	tests := []struct {
		name  string
		token string
	}{
		{"Malformed Token (No Underscore)", "invalid-token-string"},
		{"Invalid UUID Prefix", "not-a-uuid_0000000000000000000000000000000000000000000000000000000000000000"},
		{"Non-existent Token", "550e8400-e29b-41d4-a716-446655440000_1111111111111111111111111111111111111111111111111111111111111111"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"token":   tt.token,
				"agentId": uuid.New().String(),
			})
			req := httptest.NewRequest("POST", "/api/v1/auth/support/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("Expected 401 Unauthorized, got %d", rec.Code)
			}

			pd := parseProblemDetails(t, rec)
			if pd["title"] != "SUPPORT_LOGIN_FAILED" {
				t.Errorf("Expected title 'SUPPORT_LOGIN_FAILED', got '%v'", pd["title"])
			}
		})
	}
}
