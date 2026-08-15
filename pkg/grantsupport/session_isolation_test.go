package grantsupport_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/security"
	_ "modernc.org/sqlite"
)

func setupTestEngine(t *testing.T) (*grantsupport.Engine, *sql.DB) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	return engine, db
}

func TestSessionManagement_CrossTenantIsolationAndTermination(t *testing.T) {
	engine, db := setupTestEngine(t)
	defer db.Close()
	defer engine.Close()

	ctx := context.Background()

	instA := uuid.New()
	instB := uuid.New()
	adminA := uuid.New()
	adminB := uuid.New()
	agentX := uuid.New()

	// 1. Admin A creates a grant in Institution A, and Agent X redeems it -> Session A1
	tokenA, err := engine.CreateSupportGrant(ctx, instA, adminA, 60, "BILLING_READ", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant A failed: %v", err)
	}
	tenantIDA, jwtA, err := engine.SupportLogin(ctx, tokenA, agentX)
	if err != nil {
		t.Fatalf("SupportLogin A failed: %v", err)
	}
	if tenantIDA != instA {
		t.Fatalf("expected tenant %s, got %s", instA, tenantIDA)
	}

	// 2. Admin B creates a grant in Institution B, and Agent X redeems it -> Session B1
	tokenB, err := engine.CreateSupportGrant(ctx, instB, adminB, 120, "SUPPORT_FULL", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant B failed: %v", err)
	}
	tenantIDB, jwtB, err := engine.SupportLogin(ctx, tokenB, agentX)
	if err != nil {
		t.Fatalf("SupportLogin B failed: %v", err)
	}
	if tenantIDB != instB {
		t.Fatalf("expected tenant %s, got %s", instB, tenantIDB)
	}

	// 3. Institution A queries active sessions -> Must return ONLY Session A1
	sessionsA, err := engine.GetActiveSessions(ctx, instA)
	if err != nil {
		t.Fatalf("GetActiveSessions A failed: %v", err)
	}
	if len(sessionsA) != 1 {
		t.Fatalf("expected 1 active session in Institution A, got %d", len(sessionsA))
	}
	if sessionsA[0].InstitutionID != instA {
		t.Fatalf("expected institution %s, got %s", instA, sessionsA[0].InstitutionID)
	}
	if sessionsA[0].UsedByID != agentX {
		t.Fatalf("expected agent %s, got %s", agentX, sessionsA[0].UsedByID)
	}

	// 4. Institution B queries active sessions -> Must return ONLY Session B1
	sessionsB, err := engine.GetActiveSessions(ctx, instB)
	if err != nil {
		t.Fatalf("GetActiveSessions B failed: %v", err)
	}
	if len(sessionsB) != 1 {
		t.Fatalf("expected 1 active session in Institution B, got %d", len(sessionsB))
	}
	if sessionsB[0].InstitutionID != instB {
		t.Fatalf("expected institution %s, got %s", instB, sessionsB[0].InstitutionID)
	}

	// 5. Cross-Tenant Termination Attempt: Admin A attempts to terminate Grant B1 (belonging to Institution B)
	grantB1ID := sessionsB[0].GrantID
	err = engine.TerminateSession(ctx, instA, adminA, grantB1ID)
	if err == nil {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Institution A was able to terminate Institution B's grant!")
	}

	// Verify Session B1 is STILL active in Institution B
	sessionsBAfterAttack, err := engine.GetActiveSessions(ctx, instB)
	if err != nil || len(sessionsBAfterAttack) != 1 {
		t.Fatalf("Session B1 should remain active, got %d sessions (err: %v)", len(sessionsBAfterAttack), err)
	}

	// 6. Legitimate Termination: Admin A terminates Session A1
	grantA1ID := sessionsA[0].GrantID
	if err := engine.TerminateSession(ctx, instA, adminA, grantA1ID); err != nil {
		t.Fatalf("legitimate TerminateSession A1 failed: %v", err)
	}

	// Verify Institution A now has ZERO active sessions
	sessionsAAfter, err := engine.GetActiveSessions(ctx, instA)
	if err != nil {
		t.Fatalf("GetActiveSessions A failed: %v", err)
	}
	if len(sessionsAAfter) != 0 {
		t.Fatalf("expected 0 active sessions in Institution A after termination, got %d", len(sessionsAAfter))
	}

	// 7. CRITICAL SECURITY INVARIANT: Verify that Terminating A1 DID NOT invalidate Session B1!
	// Test JWT authentication middleware against Session B1
	authMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	authHandler := engine.AuthMiddleware()(authMux)

	// Test Session B1 JWT -> MUST SUCCEED (200 OK)
	reqB := httptest.NewRequest(http.MethodGet, "/protected", nil)
	reqB.Header.Set("Authorization", "Bearer "+jwtB)
	recB := httptest.NewRecorder()
	authHandler.ServeHTTP(recB, reqB)

	if recB.Code != http.StatusOK {
		t.Fatalf("CRITICAL ISOLATION BREACH: Terminating Session A1 in Institution A invalidated Session B1 in Institution B! Response: %d %s", recB.Code, recB.Body.String())
	}

	// Test Session A1 JWT -> MUST BE REJECTED (401 Unauthorized / TOKEN_REVOKED)
	reqA := httptest.NewRequest(http.MethodGet, "/protected", nil)
	reqA.Header.Set("Authorization", "Bearer "+jwtA)
	recA := httptest.NewRecorder()
	authHandler.ServeHTTP(recA, reqA)

	if recA.Code != http.StatusUnauthorized {
		t.Fatalf("expected terminated session JWT to be rejected with 401, got %d: %s", recA.Code, recA.Body.String())
	}
}

func TestSessionManagement_HTTPEndpointsEndToEnd(t *testing.T) {
	engine, db := setupTestEngine(t)
	defer db.Close()
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// 1. Generate Admin JWT for authorization
	adminJWT, err := security.GenerateJWT(adminID.String(), instID.String(), "ADMIN", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate admin JWT: %v", err)
	}

	mux := engine.HTTPHandler()

	payload := `{"durationMinutes": 60, "scope": "READ_ONLY"}`
	grantReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/grant", strings.NewReader(payload))
	grantReq.Header.Set("Authorization", "Bearer "+adminJWT)
	grantReq.Header.Set("Content-Type", "application/json")
	grantRec := httptest.NewRecorder()
	mux.ServeHTTP(grantRec, grantReq)

	if grantRec.Code != http.StatusCreated {
		t.Fatalf("POST /grant failed: %d %s", grantRec.Code, grantRec.Body.String())
	}

	var grantResp struct {
		Success bool   `json:"success"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(grantRec.Body.Bytes(), &grantResp); err != nil {
		t.Fatalf("failed to decode grant response: %v", err)
	}

	// 3. Agent logs in via POST /api/v1/auth/support/login
	loginPayload := `{"token": "` + grantResp.Token + `", "agentId": "` + agentID.String() + `"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", strings.NewReader(loginPayload))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	mux.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /login failed: %d %s", loginRec.Code, loginRec.Body.String())
	}

	// 4. Admin lists active sessions via GET /api/v1/auth/support/sessions
	sessReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/support/sessions", nil)
	sessReq.Header.Set("Authorization", "Bearer "+adminJWT)
	sessRec := httptest.NewRecorder()
	mux.ServeHTTP(sessRec, sessReq)

	if sessRec.Code != http.StatusOK {
		t.Fatalf("GET /sessions failed: %d %s", sessRec.Code, sessRec.Body.String())
	}

	var sessResp struct {
		Success  bool                   `json:"success"`
		Sessions []domain.ActiveSession `json:"sessions"`
	}
	if err := json.Unmarshal(sessRec.Body.Bytes(), &sessResp); err != nil {
		t.Fatalf("failed to decode sessions response: %v", err)
	}

	if len(sessResp.Sessions) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(sessResp.Sessions))
	}

	targetGrantID := sessResp.Sessions[0].GrantID

	// 5. Admin terminates the session via DELETE /api/v1/auth/support/sessions/{grantId}
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/support/sessions/"+targetGrantID.String(), nil)
	delReq.Header.Set("Authorization", "Bearer "+adminJWT)
	delRec := httptest.NewRecorder()
	mux.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE /sessions/{id} failed: %d %s", delRec.Code, delRec.Body.String())
	}

	// 6. Verify session list is now empty
	sessReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/support/sessions", nil)
	sessReq2.Header.Set("Authorization", "Bearer "+adminJWT)
	sessRec2 := httptest.NewRecorder()
	mux.ServeHTTP(sessRec2, sessReq2)

	if sessRec2.Code != http.StatusOK {
		t.Fatalf("GET /sessions failed: %d %s", sessRec2.Code, sessRec2.Body.String())
	}

	var sessResp2 struct {
		Success  bool                   `json:"success"`
		Sessions []domain.ActiveSession `json:"sessions"`
	}
	_ = json.Unmarshal(sessRec2.Body.Bytes(), &sessResp2)
	if len(sessResp2.Sessions) != 0 {
		t.Fatalf("expected 0 active sessions after termination, got %d", len(sessResp2.Sessions))
	}
}
