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
	returnedInstID, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
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
