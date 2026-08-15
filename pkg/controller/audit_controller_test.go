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
