package grantsupport_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/domain"
	"grantsupport/pkg/grantsupport"
)

func TestAccessRequest_20ConcurrentMutations_SingleWinner(t *testing.T) {
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

	instID := uuid.Must(uuid.NewV7())
	agentID := uuid.Must(uuid.NewV7())

	// Create a single pending access request
	req, err := engine.CreateAccessRequest(ctx, instID, agentID, domain.CreateAccessRequestInput{
		TargetService:   "concurrency-test-service",
		Reason:          "Stress testing concurrent resolution",
		DurationMinutes: 30,
	})
	if err != nil {
		t.Fatalf("failed to create access request: %v", err)
	}

	concurrency := 20
	var wg sync.WaitGroup
	var successCount int32
	var failureCount int32

	// Launch 20 concurrent operations:
	// - 10 Approvals (different admin actors)
	// - 5 Rejections
	// - 5 Cancellations
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		actorID := uuid.Must(uuid.NewV7())
		opType := i % 3

		go func(op int, actor uuid.UUID) {
			defer wg.Done()

			switch op {
			case 0: // Approve
				_, err := engine.ApproveAccessRequest(ctx, instID, actor, req.ID, domain.ApproveAccessRequestInput{})
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&failureCount, 1)
				}
			case 1: // Reject
				err := engine.RejectAccessRequest(ctx, instID, actor, req.ID, domain.RejectAccessRequestInput{RejectionReason: "Concurrent reject"})
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&failureCount, 1)
				}
			case 2: // Cancel
				err := engine.CancelAccessRequest(ctx, instID, actor, req.ID, true)
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&failureCount, 1)
				}
			}
		}(opType, actorID)
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("CRITICAL CONCURRENCY FAILURE: Expected EXACTLY 1 successful state transition, got %d successes and %d failures",
			successCount, failureCount)
	}

	if failureCount != int32(concurrency-1) {
		t.Fatalf("Expected exactly %d failures, got %d", concurrency-1, failureCount)
	}

	// Verify final state of the request
	finalReq, err := engine.GetAccessRequest(ctx, instID, req.ID)
	if err != nil {
		t.Fatalf("failed to fetch final request: %v", err)
	}

	if finalReq.Status == domain.AccessRequestStatusPending {
		t.Fatalf("request is still PENDING after concurrent operations")
	}

	t.Logf("Concurrency test passed: Exactly 1 winner transitioned request to %s, 19 operations failed closed", finalReq.Status)
}
