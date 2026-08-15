package grantsupport_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
)

func TestEmbeddedEngineLifecycle(t *testing.T) {
	ctx := context.Background()

	// 1. Open caller-managed SQLite in-memory database
	db, err := sql.Open("sqlite", "file:grantsupport_engine_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	// 2. Initialize GrantSupport Engine via functional options
	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("Failed to initialize GrantSupport Engine: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Errorf("Engine.Close failed: %v", err)
		}
		// Verify caller database connection pool is still active
		if err := db.Ping(); err != nil {
			t.Errorf("Caller database was unexpectedly closed: %v", err)
		}
	}()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// 3. Test Direct Go API: CreateSupportGrant
	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "BILLING_ONLY", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected non-empty raw grant token")
	}

	// 4. Test Direct Go API: SupportLogin
	returnedInstID, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID, "127.0.0.1")
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}
	if returnedInstID != instID {
		t.Fatalf("Expected institution ID %s, got %s", instID, returnedInstID)
	}
	if jwtToken == "" {
		t.Fatal("Expected non-empty JWT token")
	}

	// Verify JWT claims
	claims, err := security.VerifyJWT(jwtToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claims.Scope != "BILLING_ONLY" {
		t.Fatalf("Expected claims.Scope = BILLING_ONLY, got: %s", claims.Scope)
	}

	// 5. Test Cryptographic Audit Chain Verification
	valid, err := engine.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("VerifyAuditChain failed: valid=%v, err=%v", valid, err)
	}

	// 6. Test Audit Event Pagination
	events, err := engine.GetAuditEvents(ctx, instID, 10, 0)
	if err != nil {
		t.Fatalf("GetAuditEvents failed: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("Expected at least 2 audit events (granted + logged in), got %d", len(events))
	}

	// 7. Test HTTP Handler Mount & Login Endpoint
	handler := engine.HTTPHandler()

	// Create second grant for HTTP login test
	rawToken2, err := engine.CreateSupportGrant(ctx, instID, adminID, 30, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant 2 failed: %v", err)
	}

	loginPayload, _ := json.Marshal(map[string]string{
		"token":   rawToken2,
		"agentId": agentID.String(),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("HTTP /api/v1/auth/support/login returned status %d: %s", w.Code, w.Body.String())
	}

	// 8. Test Direct Go API: RevokeSupportGrant
	if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("RevokeSupportGrant failed: %v", err)
	}

	// 9. Verify Final Audit Chain
	valid, err = engine.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("Final audit chain verification failed: %v", err)
	}
}

func TestEngineWithEntClientOwnership(t *testing.T) {
	ctx := context.Background()

	db, err := sql.Open("sqlite", "file:grantsupport_entclient_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	callerEntClient, err := baseRepo.GetClient(ctx)
	if err != nil {
		t.Fatalf("Failed to get Ent client: %v", err)
	}

	// Initialize Engine injecting caller's *ent.Client
	engine, err := grantsupport.NewEngine(
		grantsupport.WithEntClient(callerEntClient),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine with EntClient failed: %v", err)
	}

	instID := uuid.New()
	adminID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 45, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected valid raw token")
	}

	// Close engine
	if err := engine.Close(); err != nil {
		t.Fatalf("Engine.Close failed: %v", err)
	}

	// Verify caller's *ent.Client is still fully active and queryable
	count, err := callerEntClient.SupportGrant.Query().Count(ctx)
	if err != nil {
		t.Fatalf("Caller Ent client query failed after engine.Close: %v", err)
	}
	if count != 1 {
		t.Fatalf("Expected 1 grant record in caller Ent client, got: %d", count)
	}
}

func TestEngineWithPgxPoolOwnership(t *testing.T) {
	connStr := os.Getenv("TEST_POSTGRES_URL")
	if connStr == "" {
		t.Skip("Skipping TestEngineWithPgxPoolOwnership: TEST_POSTGRES_URL not configured")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("Failed to create pgxpool: %v", err)
	}
	defer pool.Close()

	// Initialize Engine injecting caller's *pgxpool.Pool via WithPgxPool
	engine, err := grantsupport.NewEngine(
		grantsupport.WithPgxPool(pool),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine with WithPgxPool failed: %v", err)
	}

	instID := uuid.New()
	adminID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 30, "BILLING_ONLY", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected non-empty raw grant token")
	}

	// Close engine
	if err := engine.Close(); err != nil {
		t.Fatalf("Engine.Close failed: %v", err)
	}

	// Verify caller's *pgxpool.Pool is still fully functional and usable
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("Caller pgxpool was unexpectedly closed or unusable after engine.Close(): %v", err)
	}

	var dummy int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&dummy); err != nil || dummy != 1 {
		t.Fatalf("Caller pgxpool query failed after engine.Close(): %v", err)
	}
}

func TestAdminEndpoints_RBACEnforcement(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_rbac_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
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

	handler := engine.HTTPHandler()
	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()
	regularUserID := uuid.New()

	// 1. Generate JWT tokens for different roles
	adminJWT, err := security.GenerateJWT(adminID.String(), instID.String(), "ADMIN", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT ADMIN failed: %v", err)
	}

	ownerJWT, err := security.GenerateJWT(adminID.String(), instID.String(), "OWNER", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT OWNER failed: %v", err)
	}

	agentJWT, err := security.GenerateJWT(agentID.String(), instID.String(), "SUPPORT_AGENT", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT SUPPORT_AGENT failed: %v", err)
	}

	userJWT, err := security.GenerateJWT(regularUserID.String(), instID.String(), "USER", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT USER failed: %v", err)
	}

	grantBody := []byte(`{"durationMinutes":60,"scope":"FULL_ACCESS"}`)

	// Case A: ADMIN role succeeds (201 Created)
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/grant", bytes.NewReader(grantBody))
	reqAdmin.Header.Set("Content-Type", "application/json")
	reqAdmin.Header.Set("Authorization", "Bearer "+adminJWT)
	recAdmin := httptest.NewRecorder()
	handler.ServeHTTP(recAdmin, reqAdmin)
	if recAdmin.Code != http.StatusCreated {
		t.Fatalf("ADMIN expected 201 Created on /grant, got: %d (%s)", recAdmin.Code, recAdmin.Body.String())
	}

	// Case B: OWNER role succeeds (201 Created)
	reqOwner := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/grant", bytes.NewReader(grantBody))
	reqOwner.Header.Set("Content-Type", "application/json")
	reqOwner.Header.Set("Authorization", "Bearer "+ownerJWT)
	recOwner := httptest.NewRecorder()
	handler.ServeHTTP(recOwner, reqOwner)
	if recOwner.Code != http.StatusCreated {
		t.Fatalf("OWNER expected 201 Created on /grant, got: %d (%s)", recOwner.Code, recOwner.Body.String())
	}

	// Case C: SUPPORT_AGENT role is rejected with 403 Forbidden
	reqAgent := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/grant", bytes.NewReader(grantBody))
	reqAgent.Header.Set("Content-Type", "application/json")
	reqAgent.Header.Set("Authorization", "Bearer "+agentJWT)
	recAgent := httptest.NewRecorder()
	handler.ServeHTTP(recAgent, reqAgent)
	if recAgent.Code != http.StatusForbidden {
		t.Fatalf("SUPPORT_AGENT expected 403 Forbidden on /grant, got: %d (%s)", recAgent.Code, recAgent.Body.String())
	}

	// Case D: Standard USER role is rejected with 403 Forbidden
	reqUser := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/grant", bytes.NewReader(grantBody))
	reqUser.Header.Set("Content-Type", "application/json")
	reqUser.Header.Set("Authorization", "Bearer "+userJWT)
	recUser := httptest.NewRecorder()
	handler.ServeHTTP(recUser, reqUser)
	if recUser.Code != http.StatusForbidden {
		t.Fatalf("USER expected 403 Forbidden on /grant, got: %d (%s)", recUser.Code, recUser.Body.String())
	}

	// Case E: Revoke endpoint also enforces RBAC (ADMIN succeeds, USER rejected)
	reqRevokeUser := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/revoke", nil)
	reqRevokeUser.Header.Set("Authorization", "Bearer "+userJWT)
	recRevokeUser := httptest.NewRecorder()
	handler.ServeHTTP(recRevokeUser, reqRevokeUser)
	if recRevokeUser.Code != http.StatusForbidden {
		t.Fatalf("USER expected 403 Forbidden on /revoke, got: %d", recRevokeUser.Code)
	}

	reqRevokeAdmin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/revoke", nil)
	reqRevokeAdmin.Header.Set("Authorization", "Bearer "+adminJWT)
	recRevokeAdmin := httptest.NewRecorder()
	handler.ServeHTTP(recRevokeAdmin, reqRevokeAdmin)
	if recRevokeAdmin.Code != http.StatusOK {
		t.Fatalf("ADMIN expected 200 OK on /revoke, got: %d", recRevokeAdmin.Code)
	}
}

type mockCustomRevocationStore struct {
	isRevoked bool
	called    bool
}

func (m *mockCustomRevocationStore) IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error) {
	m.called = true
	return m.isRevoked, nil
}

func (m *mockCustomRevocationStore) GetUserTokenVersion(ctx context.Context, institutionID, userID string) (int, error) {
	return 1, nil
}

func (m *mockCustomRevocationStore) RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error {
	m.isRevoked = true
	return nil
}

func TestEngine_WithEntClient_WorkingRevocation(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_ent_revoc_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	callerEntClient, err := baseRepo.GetClient(ctx)
	if err != nil {
		t.Fatalf("Failed to get Ent client: %v", err)
	}

	// Initialize Engine injecting caller's *ent.Client without explicit RevocationStore
	engine, err := grantsupport.NewEngine(
		grantsupport.WithEntClient(callerEntClient),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine with EntClient failed: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	_, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}

	authHandler := engine.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("AUTHENTICATED"))
	}))

	// 1. Initial valid request succeeds
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rec := httptest.NewRecorder()
	authHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid JWT with EntClient-backed revocation, got: %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestEngine_WithCustomRevocationStore(t *testing.T) {
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_custom_revoc_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	customStore := &mockCustomRevocationStore{isRevoked: true}

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithRevocationStore(customStore),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine with custom RevocationStore failed: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	agentID := uuid.New()
	jwtToken, err := security.GenerateJWT(agentID.String(), instID.String(), "ADMIN", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	authHandler := engine.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rec := httptest.NewRecorder()

	authHandler.ServeHTTP(rec, req)
	if !customStore.called {
		t.Fatal("Expected custom RevocationStore to be invoked during auth check")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for revoked token via custom store, got: %d", rec.Code)
	}
}

func TestEngine_ProductionJWTKeysRequired(t *testing.T) {
	db, err := sql.Open("sqlite", "file:grantsupport_prod_key_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	// Ensure environment keys are empty
	os.Unsetenv("JWT_PRIVATE_KEY")
	os.Unsetenv("JWT_PUBLIC_KEY")

	_, err = grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithEnvironment("production"),
		grantsupport.WithAutoMigrate(false),
	)
	if err == nil {
		t.Fatal("Expected NewEngine to fail in production mode without explicit JWT keys")
	}
}

func TestEngine_DevelopmentWithoutKeysUsesTransientKeys(t *testing.T) {
	db, err := sql.Open("sqlite", "file:grantsupport_dev_key_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	os.Unsetenv("JWT_PRIVATE_KEY")
	os.Unsetenv("JWT_PUBLIC_KEY")

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithEnvironment("development"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("Expected NewEngine in development mode to succeed with transient keys, got: %v", err)
	}
	defer engine.Close()
}

func TestEngine_ProductionWithValidKeysSucceeds(t *testing.T) {
	db, err := sql.Open("sqlite", "file:grantsupport_prod_validkey_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	privPEM, pubPEM, err := security.GenerateRSAKeypairPEM()
	if err != nil {
		t.Fatalf("Failed to generate test RSA keypair: %v", err)
	}

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithEnvironment("production"),
		grantsupport.WithJWTKeys(privPEM, pubPEM),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("Expected NewEngine in production mode with explicit keys to succeed, got: %v", err)
	}
	defer engine.Close()
}
