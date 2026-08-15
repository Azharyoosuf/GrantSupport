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
	"grantsupport/pkg/repository"
)

func TestAccessRequest_CrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
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
	defer engine.Close()

	instA := uuid.Must(uuid.NewV7())
	agentA := uuid.Must(uuid.NewV7())

	instB := uuid.Must(uuid.NewV7())
	adminB := uuid.Must(uuid.NewV7())
	agentB := uuid.Must(uuid.NewV7())

	// 1. Institution A creates Request A1
	reqA, err := engine.CreateAccessRequest(ctx, instA, agentA, domain.CreateAccessRequestInput{
		TargetService:   "sensitive-financial-db",
		Reason:          "Institution A audit reconciliation",
		DurationMinutes: 60,
	})
	if err != nil {
		t.Fatalf("failed to create Tenant A request: %v", err)
	}

	// 2. Institution B attempts to GET Request A1 -> MUST FAIL with Not Found
	_, err = engine.GetAccessRequest(ctx, instB, reqA.ID)
	if err == nil || !errors.Is(err, repository.ErrAccessRequestNotFound) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Tenant B was able to fetch Tenant A request or got unexpected error: %v", err)
	}

	// 3. Institution B Admin attempts to APPROVE Request A1 -> MUST FAIL with Not Found
	_, err = engine.ApproveAccessRequest(ctx, instB, adminB, reqA.ID, domain.ApproveAccessRequestInput{})
	if err == nil || !errors.Is(err, repository.ErrAccessRequestNotFound) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Tenant B was able to approve Tenant A request: %v", err)
	}

	// 4. Institution B Admin attempts to REJECT Request A1 -> MUST FAIL with Not Found
	err = engine.RejectAccessRequest(ctx, instB, adminB, reqA.ID, domain.RejectAccessRequestInput{RejectionReason: "Malicious rejection"})
	if err == nil || !errors.Is(err, repository.ErrAccessRequestNotFound) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Tenant B was able to reject Tenant A request: %v", err)
	}

	// 5. Institution B attempts to CANCEL Request A1 -> MUST FAIL with Not Found
	err = engine.CancelAccessRequest(ctx, instB, agentB, reqA.ID, true)
	if err == nil || !errors.Is(err, repository.ErrAccessRequestNotFound) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Tenant B was able to cancel Tenant A request: %v", err)
	}

	// 6. Institution B lists requests -> Request A1 must NOT be in the results
	requestsB, err := engine.ListAccessRequests(ctx, instB, "", nil, 20, 0)
	if err != nil {
		t.Fatalf("failed to list Tenant B requests: %v", err)
	}
	if len(requestsB) != 0 {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Tenant B request list contained %d items (expected 0): %+v", len(requestsB), requestsB)
	}
}
