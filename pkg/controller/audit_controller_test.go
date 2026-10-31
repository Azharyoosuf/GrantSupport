package controller_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
	_ "modernc.org/sqlite"
)

func setupTestAuditDB(t *testing.T) (*repository.BaseRepository, *sql.DB) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	client, err := baseRepo.GetClient(context.Background())
	if err != nil {
		t.Fatalf("failed to get client: %v", err)
	}

	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("failed to auto-migrate: %v", err)
	}

	return baseRepo, db
}

func TestAuditController_GetAuditEventsAndMultiTenantIsolation(t *testing.T) {
	if err := security.SetupTestRSAKeys(); err != nil {
		t.Fatalf("failed to setup RSA keys: %v", err)
	}

	baseRepo, db := setupTestAuditDB(t)
	defer db.Close()
	defer baseRepo.MasterClient.Close()

	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	auditService := service.NewSecurityAuditService(auditRepo)
	auditCtrl := controller.NewAuditController(auditService)

	instA := uuid.New()
	instB := uuid.New()
	adminA := uuid.New()
	adminB := uuid.New()
	agent1 := uuid.New()

	ctx := context.Background()

	// Seed audit events for Institution A
	_, err := auditRepo.LogSecurityEvent(ctx, instA, adminA, "SUPPORT_ACCESS_GRANTED", "Grant created by Admin A", nil)
	if err != nil {
		t.Fatalf("log event failed: %v", err)
	}
	_, err = auditRepo.LogSecurityEvent(ctx, instA, agent1, "SUPPORT_ACCESS_LOGGED_IN", "Login by Agent 1", nil)
	if err != nil {
		t.Fatalf("log event failed: %v", err)
	}

	// Seed audit event for Institution B
	_, err = auditRepo.LogSecurityEvent(ctx, instB, adminB, "SUPPORT_ACCESS_GRANTED", "Grant created by Admin B", nil)
	if err != nil {
		t.Fatalf("log event failed: %v", err)
	}

	// Request audit events as Institution A Admin
	handler := controller.CatchAsync(auditCtrl.GetAuditEvents)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?limit=10", nil)
	req = req.WithContext(pkgctx.WithTenant(req.Context(), &pkgctx.TenantData{
		InstitutionID: instA,
		UserID:        adminA,
		Role:          "ADMIN",
	}))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Events  []struct {
			ID            uuid.UUID `json:"id"`
			InstitutionID uuid.UUID `json:"institution_id"`
			ActorID       uuid.UUID `json:"actor_id"`
			EventType     string    `json:"event_type"`
			Description   string    `json:"description"`
			HashChain     string    `json:"hash_chain"`
		} `json:"events"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if len(resp.Events) != 2 {
		t.Fatalf("expected 2 events for Institution A, got %d", len(resp.Events))
	}

	// Verify Tenant Isolation: None of the returned events belong to Institution B
	for _, ev := range resp.Events {
		if ev.InstitutionID != instA {
			t.Fatalf("CROSS-TENANT AUDIT LEAKAGE DETECTED! Expected institution %s, got %s", instA, ev.InstitutionID)
		}
	}
}

func TestAuditController_VerifyAuditChain(t *testing.T) {
	baseRepo, db := setupTestAuditDB(t)
	defer db.Close()
	defer baseRepo.MasterClient.Close()

	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	auditService := service.NewSecurityAuditService(auditRepo)
	auditCtrl := controller.NewAuditController(auditService)

	instID := uuid.New()
	adminID := uuid.New()

	ctx := context.Background()
	_, _ = auditRepo.LogSecurityEvent(ctx, instID, adminID, "EVENT_1", "Desc 1", nil)
	_, _ = auditRepo.LogSecurityEvent(ctx, instID, adminID, "EVENT_2", "Desc 2", nil)

	handler := controller.CatchAsync(auditCtrl.VerifyAuditChain)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/verify", nil)
	req = req.WithContext(pkgctx.WithTenant(req.Context(), &pkgctx.TenantData{
		InstitutionID: instID,
		UserID:        adminID,
		Role:          "ADMIN",
	}))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Valid   bool `json:"valid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Valid {
		t.Fatalf("expected valid hash chain, got invalid")
	}
}

func TestAuditController_VerifyAuditChain_BrokenChainAndQueryErrorDoNotLeak(t *testing.T) {
	baseRepo, db := setupTestAuditDB(t)
	defer db.Close()
	defer baseRepo.MasterClient.Close()

	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	auditService := service.NewSecurityAuditService(auditRepo)
	auditCtrl := controller.NewAuditController(auditService)

	instID := uuid.New()
	adminID := uuid.New()

	ctx := context.Background()
	_, err := auditRepo.LogSecurityEvent(ctx, instID, adminID, "EVENT_1", "Original description 1", nil)
	if err != nil {
		t.Fatalf("LogSecurityEvent 1 failed: %v", err)
	}
	ev2, err := auditRepo.LogSecurityEvent(ctx, instID, adminID, "EVENT_2", "Original description 2", nil)
	if err != nil {
		t.Fatalf("LogSecurityEvent 2 failed: %v", err)
	}

	// Tamper with the second event in the database so the hash chain is broken
	if _, err := db.ExecContext(ctx, `UPDATE gs_audit_events SET description = 'Tampered description' WHERE id = ?`, ev2.ID); err != nil {
		t.Fatalf("failed to tamper with audit row: %v", err)
	}

	handler := controller.CatchAsync(auditCtrl.VerifyAuditChain)

	// 1. Broken chain must return HTTP 200 with {"valid": false} and must not leak internal expected/got hashes
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/verify", nil)
	req = req.WithContext(pkgctx.WithTenant(req.Context(), &pkgctx.TenantData{
		InstitutionID: instID,
		UserID:        adminID,
		Role:          "ADMIN",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 when audit chain is broken, got %d: %s", rec.Code, rec.Body.String())
	}

	var verifyResp struct {
		Success bool   `json:"success"`
		Valid   bool   `json:"valid"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if verifyResp.Valid {
		t.Fatalf("expected valid=false when audit chain is broken, got valid=true (body: %s)", rec.Body.String())
	}
	if bytesContainsAny(rec.Body.String(), "expected ", "got ", ev2.ID.String()) {
		t.Fatalf("response leaked internal hash violation details: %s", rec.Body.String())
	}

	// 2. Real database query failure must return HTTP 500 with a generic message (no raw SQL driver error)
	_ = db.Close()
	reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/audit/verify", nil)
	reqErr = reqErr.WithContext(pkgctx.WithTenant(reqErr.Context(), &pkgctx.TenantData{
		InstitutionID: instID,
		UserID:        adminID,
		Role:          "ADMIN",
	}))
	recErr := httptest.NewRecorder()
	handler.ServeHTTP(recErr, reqErr)

	if recErr.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 on real DB query failure, got %d: %s", recErr.Code, recErr.Body.String())
	}
	if bytesContainsAny(recErr.Body.String(), "sql:", "database is closed") {
		t.Fatalf("HTTP 500 response leaked raw SQL driver error: %s", recErr.Body.String())
	}
}

func bytesContainsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if len(n) > 0 && len(haystack) >= len(n) {
			for i := 0; i <= len(haystack)-len(n); i++ {
				if haystack[i:i+len(n)] == n {
					return true
				}
			}
		}
	}
	return false
}
