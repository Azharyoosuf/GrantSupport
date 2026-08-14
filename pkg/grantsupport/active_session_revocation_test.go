package grantsupport_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/cache"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

// setupTestEngineWithSQLRevocation creates a real embedded Engine backed by SQLite with SQLRevocationStore and Capability Tables.
func setupTestEngineWithSQLRevocation(t *testing.T, dbName string) (*grantsupport.Engine, *sql.DB, func()) {
	t.Helper()
	_ = security.SetupTestRSAKeys()

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)", dbName)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Failed to open SQLite DB: %v", err)
	}

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		db.Close()
		t.Fatalf("Failed to create Engine: %v", err)
	}

	cleanup := func() {
		_ = engine.Close()
		_ = db.Close()
	}

	return engine, db, cleanup
}

// Test A — Admin revokes before redemption
func TestRevocation_AdminRevokesBeforeRedemption(t *testing.T) {
	ctx := context.Background()
	engine, _, cleanup := setupTestEngineWithSQLRevocation(t, "test_revoc_before_redeem")
	defer cleanup()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	// Admin revokes all grants for institution
	if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("RevokeSupportGrant failed: %v", err)
	}

	// Agent tries to redeem the revoked grant token -> must fail
	_, _, err = engine.SupportLogin(ctx, rawToken, agentID)
	if err == nil {
		t.Fatal("Expected SupportLogin to fail after grant was revoked, got err=nil")
	}
}

// Test B — Admin revokes after redemption (Active session invalidation)
func TestRevocation_AdminRevokesAfterRedemption(t *testing.T) {
	ctx := context.Background()
	engine, _, cleanup := setupTestEngineWithSQLRevocation(t, "test_revoc_after_redeem")
	defer cleanup()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	handler := engine.HTTPHandler()

	// 1. Create Grant
	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	// 2. Redeem Grant -> obtain agent JWT
	returnedInstID, agentJWT, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}
	if returnedInstID != instID {
		t.Fatalf("Expected instID %s, got %s", instID, returnedInstID)
	}

	// 3. Confirm Agent JWT is initially valid by calling agent logout or protected route
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+agentJWT)
	// We check if claims verify first
	claims, err := security.VerifyJWT(agentJWT)
	if err != nil || claims == nil {
		t.Fatalf("Agent JWT verification failed before revocation: %v", err)
	}

	// 4. Also generate an Admin JWT to prove admin session remains unaffected
	adminJWT, err := security.GenerateJWTWithVersion(adminID.String(), instID.String(), "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion for admin failed: %v", err)
	}

	// 5. Admin calls POST /api/v1/auth/support/revoke
	revokeReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/revoke", nil)
	revokeReq.Header.Set("Authorization", "Bearer "+adminJWT)
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)

	if revokeRec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on /revoke, got %d (%s)", revokeRec.Code, revokeRec.Body.String())
	}

	// 6. Attempt to use the previously issued agent JWT -> MUST BE REJECTED with 401 TOKEN_REVOKED
	testAgentReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	testAgentReq.Header.Set("Authorization", "Bearer "+agentJWT)
	testAgentRec := httptest.NewRecorder()
	handler.ServeHTTP(testAgentRec, testAgentReq)

	if testAgentRec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected HTTP 401 Unauthorized for invalidated agent JWT, got %d (%s)", testAgentRec.Code, testAgentRec.Body.String())
	}
	if !strings.Contains(testAgentRec.Body.String(), "TOKEN_REVOKED") {
		t.Fatalf("Expected RFC 7807 problem detail TOKEN_REVOKED, got: %s", testAgentRec.Body.String())
	}

	// 7. Confirm Admin's own JWT session is STILL VALID (admin was not accidentally revoked)
	adminTestReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/revoke", nil)
	adminTestReq.Header.Set("Authorization", "Bearer "+adminJWT)
	adminTestRec := httptest.NewRecorder()
	handler.ServeHTTP(adminTestRec, adminTestReq)

	if adminTestRec.Code != http.StatusOK {
		t.Fatalf("Expected admin session to remain valid (HTTP 200), got %d (%s)", adminTestRec.Code, adminTestRec.Body.String())
	}
}

// Test C — JWT still works before revocation
func TestRevocation_JWTWorksBeforeRevocation(t *testing.T) {
	ctx := context.Background()
	engine, _, cleanup := setupTestEngineWithSQLRevocation(t, "test_jwt_valid_before_revoc")
	defer cleanup()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	_, agentJWT, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}

	// Agent calls /logout while active -> should succeed with 200 OK
	handler := engine.HTTPHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	req.Header.Set("Authorization", "Bearer "+agentJWT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 for valid agent session, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// Test D — JWT expires naturally
func TestRevocation_ExpiredJWTIsRejected(t *testing.T) {
	_ = security.SetupTestRSAKeys()
	instID := uuid.New().String()
	userID := uuid.New().String()

	// Issue an already expired JWT (-10 seconds)
	expiredJWT, err := security.GenerateJWTWithVersion(userID, instID, "SUPPORT_AGENT", "FULL_ACCESS", 1, -10*time.Second)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion failed: %v", err)
	}

	_, err = security.VerifyJWT(expiredJWT)
	if err == nil {
		t.Fatal("Expected VerifyJWT to fail for expired token, got err=nil")
	}
}

// Test E — Cross-tenant protection (Institution A revocation does not affect Institution B)
func TestRevocation_CrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	engine, _, cleanup := setupTestEngineWithSQLRevocation(t, "test_cross_tenant_revoc")
	defer cleanup()

	instA := uuid.New()
	instB := uuid.New()
	adminA := uuid.New()
	adminB := uuid.New()
	agentA := uuid.New()
	agentB := uuid.New()

	handler := engine.HTTPHandler()

	// Institution A creates & redeems grant
	tokenA, err := engine.CreateSupportGrant(ctx, instA, adminA, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant A failed: %v", err)
	}
	_, jwtA, err := engine.SupportLogin(ctx, tokenA, agentA)
	if err != nil {
		t.Fatalf("SupportLogin A failed: %v", err)
	}

	// Institution B creates & redeems grant
	tokenB, err := engine.CreateSupportGrant(ctx, instB, adminB, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant B failed: %v", err)
	}
	_, jwtB, err := engine.SupportLogin(ctx, tokenB, agentB)
	if err != nil {
		t.Fatalf("SupportLogin B failed: %v", err)
	}

	// Admin B revokes Institution B's grants only
	adminBJWT, err := security.GenerateJWTWithVersion(adminB.String(), instB.String(), "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("Generate adminB JWT failed: %v", err)
	}

	revokeBReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/revoke", nil)
	revokeBReq.Header.Set("Authorization", "Bearer "+adminBJWT)
	revokeBRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeBRec, revokeBReq)

	if revokeBRec.Code != http.StatusOK {
		t.Fatalf("Revoke B failed: %d (%s)", revokeBRec.Code, revokeBRec.Body.String())
	}

	// Institution B's agent session MUST be revoked (401)
	reqB := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	reqB.Header.Set("Authorization", "Bearer "+jwtB)
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusUnauthorized {
		t.Fatalf("Expected Institution B agent to be revoked (401), got: %d", recB.Code)
	}

	// Institution A's agent session MUST REMAIN 100% VALID (200 OK)
	reqA := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	reqA.Header.Set("Authorization", "Bearer "+jwtA)
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("Expected Institution A agent session to remain valid (200), got: %d (%s)", recA.Code, recA.Body.String())
	}
}

// Test H — Revocation store failure fails closed (503)
func TestRevocation_FailClosedOnStoreError(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	instID := uuid.New().String()
	userID := uuid.New().String()
	jwtToken, err := security.GenerateJWTWithVersion(userID, instID, "SUPPORT_AGENT", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion failed: %v", err)
	}

	// Nil store -> 503
	authMiddleware := middleware.NewAuthMiddleware(nil)
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503 Service Unavailable on nil revocation store, got: %d", rec.Code)
	}
}

// Test I — Repeated revocation is safe and idempotent
func TestRevocation_RepeatedRevocationIsIdempotent(t *testing.T) {
	ctx := context.Background()
	engine, _, cleanup := setupTestEngineWithSQLRevocation(t, "test_repeated_revoc")
	defer cleanup()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	_, agentJWT, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}

	// First revocation
	if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("First RevokeSupportGrant failed: %v", err)
	}

	// Second revocation (must be safe and error-free)
	if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("Second RevokeSupportGrant failed: %v", err)
	}

	// Third revocation
	if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("Third RevokeSupportGrant failed: %v", err)
	}

	// Agent token is still revoked
	handler := engine.HTTPHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	req.Header.Set("Authorization", "Bearer "+agentJWT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized after repeated revocation, got: %d", rec.Code)
	}
}

// Test J — Agent logout voluntarily terminates session
func TestRevocation_AgentLogoutEndpoint(t *testing.T) {
	ctx := context.Background()
	engine, _, cleanup := setupTestEngineWithSQLRevocation(t, "test_agent_logout")
	defer cleanup()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	_, agentJWT, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}

	handler := engine.HTTPHandler()

	// 1. Call POST /api/v1/auth/support/logout with active agent JWT -> HTTP 200
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+agentJWT)
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)

	if logoutRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on logout, got %d (%s)", logoutRec.Code, logoutRec.Body.String())
	}

	// 2. Call again with same agent JWT -> MUST BE REJECTED with 401 TOKEN_REVOKED
	secondReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/logout", nil)
	secondReq.Header.Set("Authorization", "Bearer "+agentJWT)
	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, secondReq)

	if secondRec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for logged out agent, got %d (%s)", secondRec.Code, secondRec.Body.String())
	}

	// 3. Admin session remains valid
	adminJWT, _ := security.GenerateJWTWithVersion(adminID.String(), instID.String(), "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	adminReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/revoke", nil)
	adminReq.Header.Set("Authorization", "Bearer "+adminJWT)
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)

	if adminRec.Code != http.StatusOK {
		t.Fatalf("Expected admin session to remain valid after agent logout, got: %d", adminRec.Code)
	}
}

// Test G — SQL fallback backend active-session revocation
func TestRevocation_SQLFallbackBackend(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:test_sql_fallback_revoc?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	if err := repository.CreateCapabilityTables(ctx, db, "sqlite"); err != nil {
		t.Fatalf("CreateCapabilityTables failed: %v", err)
	}

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Schema.Create failed: %v", err)
	}

	sqlRevStore := revocation.NewSQLRevocationStore(db, "sqlite")
	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
	svc.SetRevocationStore(sqlRevStore)

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	_, agentJWT, err := svc.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}

	// Verify before revocation
	claims, err := security.VerifyJWT(agentJWT)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	revoked, err := sqlRevStore.IsTokenRevoked(ctx, claims.InstitutionID, claims.UserID, claims.TokenVersion)
	if err != nil || revoked {
		t.Fatalf("Expected token to not be revoked, got revoked=%v, err=%v", revoked, err)
	}

	// Admin revokes
	if err := svc.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("RevokeSupportGrant failed: %v", err)
	}

	// Verify after revocation -> SQL store must report revoked
	revoked, err = sqlRevStore.IsTokenRevoked(ctx, claims.InstitutionID, claims.UserID, claims.TokenVersion)
	if err != nil || !revoked {
		t.Fatalf("Expected SQL store to report token revoked, got revoked=%v, err=%v", revoked, err)
	}
}

// Test F — Redis/Valkey backend active-session revocation
func TestRevocation_RedisBackend(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	redisURL := "redis://127.0.0.1:6379/0"
	if env := os.Getenv("VALKEY_CACHE_URL"); env != "" {
		redisURL = env
	} else if env := os.Getenv("TEST_REDIS_URL"); env != "" {
		redisURL = env
	}

	valkeyClient, err := cache.NewValkeyClient(redisURL)
	if err != nil {
		// Try host.docker.internal if running inside Docker container
		valkeyClient, err = cache.NewValkeyClient("redis://host.docker.internal:6379/0")
	}
	if err != nil {
		t.Skipf("Skipping Redis revocation test (live Redis/Valkey not reachable): %v", err)
		return
	}
	defer valkeyClient.Close()

	redisRevStore := revocation.NewRedisRevocationStore(valkeyClient.Client)

	instID := uuid.New().String()
	agentID := uuid.New().String()

	// Initial token version 1
	revoked, err := redisRevStore.IsTokenRevoked(ctx, instID, agentID, 1)
	if err != nil || revoked {
		t.Fatalf("Expected token version 1 to not be revoked, got revoked=%v, err=%v", revoked, err)
	}

	// Revoke sessions by setting minimum version to 2
	if err := redisRevStore.RevokeUserSessions(ctx, instID, agentID, 2); err != nil {
		t.Fatalf("RevokeUserSessions failed: %v", err)
	}

	// Token version 1 must now be revoked
	revoked, err = redisRevStore.IsTokenRevoked(ctx, instID, agentID, 1)
	if err != nil || !revoked {
		t.Fatalf("Expected token version 1 to be revoked after version bump, got revoked=%v, err=%v", revoked, err)
	}

	// Token version 2 (new session) must NOT be revoked
	revoked, err = redisRevStore.IsTokenRevoked(ctx, instID, agentID, 2)
	if err != nil || revoked {
		t.Fatalf("Expected token version 2 to be valid, got revoked=%v, err=%v", revoked, err)
	}
}
