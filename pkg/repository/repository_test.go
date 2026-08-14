package repository_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/domain"
	"grantsupport/pkg/repository"
)

func TestBaseRepositoryGetClient(t *testing.T) {
	base := repository.NewBaseRepository(nil)
	client, err := base.GetClient(context.Background())
	if err == nil {
		t.Error("Expected error when MasterClient is nil")
	}
	if client != nil {
		t.Error("Expected client to be nil")
	}
}

func TestSupportGrantRepositoryNilClient(t *testing.T) {
	base := repository.NewBaseRepository(nil)
	repo := repository.NewSupportGrantRepository(base)

	ctx := context.Background()
	_, err := repo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID: uuid.New(),
		GrantedByID:   uuid.New(),
	})
	if err == nil {
		t.Error("Expected error when database client is nil")
	}

	_, err = repo.FindActiveGrantByTokenHash(ctx, "sample_hash")
	if err == nil {
		t.Error("Expected error when database client is nil")
	}

	err = repo.MarkGrantAsUsed(ctx, uuid.New())
	if err == nil {
		t.Error("Expected error when database client is nil")
	}

	_, err = repo.RevokeAllGrantsForInstitution(ctx, uuid.New())
	if err == nil {
		t.Error("Expected error when database client is nil")
	}
}

func TestSecurityAuditRepositoryNilClient(t *testing.T) {
	base := repository.NewBaseRepository(nil)
	repo := repository.NewSecurityAuditRepository(base)

	ctx := context.Background()
	_, err := repo.LogSecurityEvent(ctx, uuid.New(), uuid.New(), "TEST_EVENT", "Test description", nil)
	if err == nil {
		t.Error("Expected error when database client is nil")
	}
}

func TestRepositoryWithSQLiteInMemory(t *testing.T) {
	ctx := context.Background()

	// Open in-memory SQLite database with foreign keys enabled
	db, err := sql.Open("sqlite", "file:grantsupport_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open in-memory SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)

	instID := uuid.New()
	adminID := uuid.New()
	tokenHash := "test_token_hash_abc123"

	// 1. Create Support Grant
	grant, err := grantRepo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID: instID,
		GrantedByID:   adminID,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateSupportGrant failed on SQLite: %v", err)
	}
	if grant.ID == uuid.Nil || grant.TokenHash != tokenHash {
		t.Fatalf("Unexpected grant data returned: %+v", grant)
	}

	// 2. Find Active Grant
	found, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("FindActiveGrantByTokenHash failed: %v", err)
	}
	if found.ID != grant.ID || found.IsUsed {
		t.Fatalf("Grant mismatch or already marked as used: %+v", found)
	}

	// 3. Mark Grant as Used
	if err := grantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		t.Fatalf("MarkGrantAsUsed failed: %v", err)
	}

	// 4. Verify Grant is no longer active
	usedGrant, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err == nil && usedGrant != nil {
		t.Fatalf("Expected FindActiveGrantByTokenHash to return error for used grant, got: %+v", usedGrant)
	}

	// 5. Log Security Event & Verify Audit Chain
	auditEvent, err := auditRepo.LogSecurityEvent(ctx, instID, adminID, "TEST_GRANT_CREATED", "Test grant description", nil)
	if err != nil {
		t.Fatalf("LogSecurityEvent failed: %v", err)
	}
	if auditEvent.ID == uuid.Nil || auditEvent.CreatedAt.IsZero() {
		t.Fatalf("Unexpected audit event: %+v", auditEvent)
	}
}

func TestConcurrentAtomicGrantConsumption(t *testing.T) {
	ctx := context.Background()

	db, err := sql.Open("sqlite", "file:grantsupport_concurrent_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	instID := uuid.New()
	adminID := uuid.New()
	tokenHash := "concurrent_token_hash_999"

	grant, err := grantRepo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID: instID,
		GrantedByID:   adminID,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	const concurrency = 50
	var successCount int64
	var failCount int64

	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			<-startCh
			err := grantRepo.MarkGrantAsUsed(context.Background(), grant.ID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			doneCh <- struct{}{}
		}()
	}

	// Release all 50 goroutines simultaneously
	close(startCh)

	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	if successCount != 1 {
		t.Fatalf("Expected EXACTLY 1 successful consumption among 50 concurrent workers, got: %d", successCount)
	}
	if failCount != 49 {
		t.Fatalf("Expected EXACTLY 49 failed consumptions among 50 concurrent workers, got: %d", failCount)
	}
}

func TestAuditChainVerificationAndConcurrency(t *testing.T) {
	ctx := context.Background()

	db, err := sql.Open("sqlite", "file:grantsupport_auditchain_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	instID := uuid.New()
	adminID := uuid.New()

	// 1. Log sequential events and verify chain
	for i := 1; i <= 10; i++ {
		_, err := auditRepo.LogSecurityEvent(ctx, instID, adminID, "EVENT_TYPE_A", fmt.Sprintf("Event number %d with email test%d@example.com", i, i), nil)
		if err != nil {
			t.Fatalf("LogSecurityEvent %d failed: %v", i, err)
		}
	}

	valid, err := auditRepo.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("Expected audit chain to be valid, got valid=%v, err=%v", valid, err)
	}

	// 2. Log 20 concurrent events under striped institution mutex
	const concurrency = 20
	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		workerID := uuid.New()
		go func(id int) {
			<-startCh
			_, _ = auditRepo.LogSecurityEvent(context.Background(), instID, workerID, "CONCURRENT_EVENT", fmt.Sprintf("Concurrent action %d", id), nil)
			doneCh <- struct{}{}
		}(i)
	}

	close(startCh)
	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	// Verify the entire chain of 30 total events is still 100% cryptographically consistent
	valid, err = auditRepo.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("Expected concurrent audit chain to be unbroken, got valid=%v, err=%v", valid, err)
	}

	// 3. Test pagination query
	events, err := auditRepo.GetAuditEventsByInstitution(ctx, instID, 15, 0)
	if err != nil {
		t.Fatalf("GetAuditEventsByInstitution failed: %v", err)
	}
	if len(events) != 15 {
		t.Fatalf("Expected 15 events, got %d", len(events))
	}
}
