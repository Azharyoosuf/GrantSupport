package controller_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/service"
)

func setupTestAccessRequestController(t *testing.T) (*controller.AccessRequestController, *service.AccessRequestService, uuid.UUID, uuid.UUID, uuid.UUID) {
	ctx := context.Background()
	dbName := fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.New().String())
	db, err := sql.Open("sqlite", dbName)
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("failed to auto-migrate schemas: %v", err)
	}

	lockStore := lock.NewMemoryLockStore()
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	reqRepo := repository.NewAccessRequestRepository(baseRepo)

	reqService := service.NewAccessRequestService(baseRepo, reqRepo, grantRepo, auditRepo, lockStore)
	ctrl := controller.NewAccessRequestController(reqService)

	instID := uuid.Must(uuid.NewV7())
	adminID := uuid.Must(uuid.NewV7())
	agentID := uuid.Must(uuid.NewV7())

	return ctrl, reqService, instID, adminID, agentID
}

func TestAccessRequestController_FullLifecycle(t *testing.T) {
	ctrl, _, instID, adminID, agentID := setupTestAccessRequestController(t)

	// 1. Create Access Request as SUPPORT_AGENT
	createPayload := controller.CreateAccessRequestPayload{
		TargetService:   "billing-service",
		Reason:          "Investigating ticket #4829 - ledger discrepancy",
		DurationMinutes: 60,
		Scope:           "billing:read",
		WhitelistedIPs:  []string{"198.51.100.4"},
	}
	bodyBytes, _ := json.Marshal(createPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/access-requests", bytes.NewReader(bodyBytes))
	ctx := pkgctx.WithTenant(req.Context(), &pkgctx.TenantData{
		InstitutionID: instID,
		UserID:        agentID,
		Role:          "SUPPORT_AGENT",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	createHandler := controller.CatchAsync(ctrl.CreateAccessRequest)
	createHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected HTTP 201 on create, got %d: %s", rec.Code, rec.Body.String())
	}

	var createdReq domain.AccessRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &createdReq); err != nil {
		t.Fatalf("failed to unmarshal created request: %v", err)
	}

	if createdReq.Status != domain.AccessRequestStatusPending || createdReq.RequestedDurationMinutes != 60 {
		t.Errorf("unexpected created request state: %+v", createdReq)
	}

	// 2. Self-Approval Attempt MUST FAIL with HTTP 403 Forbidden
	approveURL := "/api/v1/access-requests/" + createdReq.ID.String() + "/approve"
	approveReq := httptest.NewRequest(http.MethodPost, approveURL, bytes.NewReader([]byte("{}")))
	agentCtx := pkgctx.WithTenant(approveReq.Context(), &pkgctx.TenantData{
		InstitutionID: instID,
		UserID:        agentID, // Same user who requested
		Role:          "ADMIN",
	})
	rCtx := chi.NewRouteContext()
	rCtx.URLParams.Add("id", createdReq.ID.String())
	approveReq = approveReq.WithContext(context.WithValue(agentCtx, chi.RouteCtxKey, rCtx))
	approveRec := httptest.NewRecorder()

	approveHandler := controller.CatchAsync(ctrl.ApproveAccessRequest)
	approveHandler.ServeHTTP(approveRec, approveReq)

	if approveRec.Code != http.StatusForbidden {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Self-approval did not return HTTP 403, got %d: %s", approveRec.Code, approveRec.Body.String())
	}

	// 3. Legitimate Customer Admin Approval MUST SUCCEED and return rawToken
	adminApproveReq := httptest.NewRequest(http.MethodPost, approveURL, bytes.NewReader([]byte(`{"durationMinutes": 45}`)))
	adminCtx := pkgctx.WithTenant(adminApproveReq.Context(), &pkgctx.TenantData{
		InstitutionID: instID,
		UserID:        adminID, // Different user (Customer Admin)
		Role:          "ADMIN",
	})
	adminApproveReq = adminApproveReq.WithContext(context.WithValue(adminCtx, chi.RouteCtxKey, rCtx))
	adminApproveRec := httptest.NewRecorder()

	approveHandler.ServeHTTP(adminApproveRec, adminApproveReq)

	if adminApproveRec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on admin approval, got %d: %s", adminApproveRec.Code, adminApproveRec.Body.String())
	}

	var approveResp struct {
		Success   bool      `json:"success"`
		RequestID uuid.UUID `json:"requestId"`
		Status    string    `json:"status"`
		GrantID   uuid.UUID `json:"grantId"`
		RawToken  string    `json:"rawToken"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := json.Unmarshal(adminApproveRec.Body.Bytes(), &approveResp); err != nil {
		t.Fatalf("failed to decode approval response: %v", err)
	}

	if !approveResp.Success || approveResp.Status != domain.AccessRequestStatusApproved || approveResp.RawToken == "" {
		t.Fatalf("expected approved response with rawToken, got: %+v", approveResp)
	}

	// 4. Double Approval Attempt MUST FAIL with HTTP 409 Conflict
	doubleApproveRec := httptest.NewRecorder()
	doubleApproveReq := httptest.NewRequest(http.MethodPost, approveURL, bytes.NewReader([]byte("{}")))
	doubleApproveReq = doubleApproveReq.WithContext(context.WithValue(adminCtx, chi.RouteCtxKey, rCtx))
	approveHandler.ServeHTTP(doubleApproveRec, doubleApproveReq)

	if doubleApproveRec.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409 on double approval, got %d: %s", doubleApproveRec.Code, doubleApproveRec.Body.String())
	}
}
