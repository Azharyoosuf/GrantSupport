package grantsupport_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/domain"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/service"
)

func setupTestAccessRequestEngine(t *testing.T) (*grantsupport.Engine, uuid.UUID, uuid.UUID, uuid.UUID) {
	dbName := fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.New().String())
	db, err := sql.Open("sqlite", dbName)
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

	instID := uuid.Must(uuid.NewV7())
	adminID := uuid.Must(uuid.NewV7())
	agentID := uuid.Must(uuid.NewV7())

	return engine, instID, adminID, agentID
}

func TestAccessRequest_FullE2EWorkflow(t *testing.T) {
	ctx := context.Background()
	engine, instID, adminID, agentID := setupTestAccessRequestEngine(t)
	defer engine.Close()

	// 1. Support Agent creates an Access Request
	input := domain.CreateAccessRequestInput{
		TargetService:   "payment-gateway",
		Reason:          "Investigating payment capture failures on customer invoice #1092",
		DurationMinutes: 60,
		Scope:           "billing:read,billing:write",
		WhitelistedIPs:  []string{"203.0.113.50"},
	}

	req, err := engine.CreateAccessRequest(ctx, instID, agentID, input)
	if err != nil {
		t.Fatalf("failed to create access request: %v", err)
	}

	if req.Status != domain.AccessRequestStatusPending || req.TargetService != "payment-gateway" {
		t.Fatalf("unexpected access request state: %+v", req)
	}

	// 2. Query Request by ID
	fetched, err := engine.GetAccessRequest(ctx, instID, req.ID)
	if err != nil {
		t.Fatalf("failed to fetch access request: %v", err)
	}
	if fetched.ID != req.ID || fetched.Status != domain.AccessRequestStatusPending {
		t.Fatalf("fetched request mismatch: %+v", fetched)
	}

	// 3. Customer Admin Approves Request with Duration Narrowing (45 mins)
	approveInput := domain.ApproveAccessRequestInput{
		DurationMinutes: 45,
		Scope:           "billing:read", // Approver narrowed scope
	}
	result, err := engine.ApproveAccessRequest(ctx, instID, adminID, req.ID, approveInput)
	if err != nil {
		t.Fatalf("failed to approve access request: %v", err)
	}

	if result.RawToken == "" || result.Grant == nil || result.Request.Status != domain.AccessRequestStatusApproved {
		t.Fatalf("unexpected approval result: %+v", result)
	}
	if *result.Request.ApprovedDurationMinutes != 45 || *result.Request.ApprovedScope != "billing:read" {
		t.Fatalf("expected narrowed duration (45) and scope (billing:read), got duration: %v, scope: %v",
			result.Request.ApprovedDurationMinutes, result.Request.ApprovedScope)
	}

	// 4. Support Agent Redeems Approved Grant Token via SupportLogin
	loginInstID, jwtToken, err := engine.SupportLogin(ctx, result.RawToken, agentID, "203.0.113.50")
	if err != nil {
		t.Fatalf("failed to login using approved support token: %v", err)
	}

	if loginInstID != instID || jwtToken == "" {
		t.Fatalf("invalid login response: instID=%v, token=%v", loginInstID, jwtToken)
	}

	// 5. Query Active Sessions
	sessions, err := engine.GetActiveSessions(ctx, instID)
	if err != nil {
		t.Fatalf("failed to get active sessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].GrantID != result.Grant.ID {
		t.Fatalf("expected 1 active session matching grant %s, got: %+v", result.Grant.ID, sessions)
	}

	// 6. Terminate Active Session
	if err := engine.TerminateSession(ctx, instID, adminID, result.Grant.ID); err != nil {
		t.Fatalf("failed to terminate session: %v", err)
	}

	// 7. Verify Audit Hash-Chain Integrity
	valid, err := engine.VerifyAuditChain(ctx, instID)
	if err != nil {
		t.Fatalf("audit chain verification errored: %v", err)
	}
	if !valid {
		t.Fatalf("audit chain is broken after access request lifecycle")
	}
}

func TestAccessRequest_SelfApprovalForbidden(t *testing.T) {
	ctx := context.Background()
	engine, instID, _, agentID := setupTestAccessRequestEngine(t)
	defer engine.Close()

	req, err := engine.CreateAccessRequest(ctx, instID, agentID, domain.CreateAccessRequestInput{
		Reason:          "Investigating bug",
		DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Agent attempts to approve their OWN request
	_, err = engine.ApproveAccessRequest(ctx, instID, agentID, req.ID, domain.ApproveAccessRequestInput{})
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FLAW: Self-approval succeeded when it must fail")
	}

	if !errors.Is(err, service.ErrSelfApprovalProhibited) {
		t.Fatalf("expected ErrSelfApprovalProhibited, got: %v", err)
	}
}

func TestAccessRequest_RejectionAndCancellation(t *testing.T) {
	ctx := context.Background()
	engine, instID, adminID, agentID := setupTestAccessRequestEngine(t)
	defer engine.Close()

	// 1. Rejection Test
	req1, err := engine.CreateAccessRequest(ctx, instID, agentID, domain.CreateAccessRequestInput{
		Reason:          "Need access for maintenance",
		DurationMinutes: 60,
	})
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if err := engine.RejectAccessRequest(ctx, instID, adminID, req1.ID, domain.RejectAccessRequestInput{RejectionReason: "Maintenance window postponed"}); err != nil {
		t.Fatalf("failed to reject request: %v", err)
	}

	fetched1, _ := engine.GetAccessRequest(ctx, instID, req1.ID)
	if fetched1.Status != domain.AccessRequestStatusRejected || *fetched1.RejectionReason != "Maintenance window postponed" {
		t.Fatalf("unexpected rejected request state: %+v", fetched1)
	}

	// Cannot approve a rejected request
	_, err = engine.ApproveAccessRequest(ctx, instID, adminID, req1.ID, domain.ApproveAccessRequestInput{})
	if err == nil {
		t.Fatalf("expected error approving rejected request, got nil")
	}

	// 2. Cancellation Test
	req2, err := engine.CreateAccessRequest(ctx, instID, agentID, domain.CreateAccessRequestInput{
		Reason:          "Accidental request",
		DurationMinutes: 15,
	})
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if err := engine.CancelAccessRequest(ctx, instID, agentID, req2.ID, false); err != nil {
		t.Fatalf("failed to cancel request: %v", err)
	}

	fetched2, _ := engine.GetAccessRequest(ctx, instID, req2.ID)
	if fetched2.Status != domain.AccessRequestStatusCancelled {
		t.Fatalf("expected CANCELLED status, got: %s", fetched2.Status)
	}
}

func TestAccessRequest_DirectGrantCompatibility(t *testing.T) {
	ctx := context.Background()
	engine, instID, adminID, agentID := setupTestAccessRequestEngine(t)
	defer engine.Close()

	// Direct grant flow from Milestone 1 & 2 must continue to work without regression
	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 30, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("failed to create direct support grant: %v", err)
	}

	loginInstID, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("failed direct support grant login: %v", err)
	}

	if loginInstID != instID || jwtToken == "" {
		t.Fatalf("invalid direct grant login result: %v", loginInstID)
	}
}
