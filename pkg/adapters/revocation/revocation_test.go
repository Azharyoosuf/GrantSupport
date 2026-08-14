package revocation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/security"
)

func TestRedisRevocationStore_NilClientFailsClosed(t *testing.T) {
	store := revocation.NewRedisRevocationStore(nil)
	ctx := context.Background()

	revoked, err := store.IsTokenRevoked(ctx, "inst-1", "user-1", 1)
	if err == nil {
		t.Fatalf("Expected error when Redis client is nil, got err=nil, revoked=%v", revoked)
	}

	err = store.RevokeUserSessions(ctx, "inst-1", "user-1", 2)
	if err == nil {
		t.Fatalf("Expected error when calling RevokeUserSessions with nil Redis client")
	}
}

func TestSQLRevocationStore_NilDBFailsClosed(t *testing.T) {
	store := revocation.NewSQLRevocationStore(nil, "postgres")
	ctx := context.Background()

	revoked, err := store.IsTokenRevoked(ctx, "inst-1", "user-1", 1)
	if err == nil {
		t.Fatalf("Expected error when SQL DB is nil, got err=nil, revoked=%v", revoked)
	}

	err = store.RevokeUserSessions(ctx, "inst-1", "user-1", 2)
	if err == nil {
		t.Fatalf("Expected error when calling RevokeUserSessions with nil SQL DB")
	}
}

func TestAuthMiddleware_NilRevocationStoreFailsClosedWith503(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	instID := uuid.New().String()
	userID := uuid.New().String()
	jwtToken, err := security.GenerateJWTWithVersion(userID, instID, "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion failed: %v", err)
	}

	// Create AuthMiddleware wrapping a nil client RedisRevocationStore
	nilRevStore := revocation.NewRedisRevocationStore(nil)
	authMiddleware := middleware.NewAuthMiddleware(nilRevStore)

	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/grant", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Must fail closed with 503 Service Unavailable, NEVER 200 OK
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected fail-closed 503 Service Unavailable, got: %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_ExplicitNilStoreFailsClosedWith503(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	instID := uuid.New().String()
	userID := uuid.New().String()
	jwtToken, err := security.GenerateJWTWithVersion(userID, instID, "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion failed: %v", err)
	}

	authMiddleware := middleware.NewAuthMiddleware(nil)

	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/grant", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected fail-closed 503 Service Unavailable for nil store, got: %d (%s)", rec.Code, rec.Body.String())
	}
}

type mockRevokedStore struct{}

func (m *mockRevokedStore) IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error) {
	return true, nil
}

func (m *mockRevokedStore) RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error {
	return nil
}

func TestAuthMiddleware_RevokedTokenReturns401(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	instID := uuid.New().String()
	userID := uuid.New().String()
	jwtToken, err := security.GenerateJWTWithVersion(userID, instID, "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion failed: %v", err)
	}

	authMiddleware := middleware.NewAuthMiddleware(&mockRevokedStore{})

	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/grant", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for revoked token, got: %d (%s)", rec.Code, rec.Body.String())
	}
}
