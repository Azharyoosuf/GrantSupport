package service_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

func TestGrantSupportServiceValidation(t *testing.T) {
	svc := service.NewGrantSupportService(nil, nil, nil)

	t.Run("CreateSupportGrant fails with nil repository", func(t *testing.T) {
		_, err := svc.CreateSupportGrant(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), 60)
		if err == nil {
			t.Errorf("Expected error when supportGrantRepo is nil")
		}
	})

	t.Run("CreateSupportGrant fails with invalid duration (0 minutes)", func(t *testing.T) {
		_, err := svc.CreateSupportGrant(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), 0)
		if err == nil {
			t.Errorf("Expected error for 0 minutes duration")
		}
	})

	t.Run("SupportLogin fails with nil agent UUID", func(t *testing.T) {
		_, _, err := svc.SupportLogin(context.Background(), "11111111-1111-1111-1111-111111111111_abcdef", uuid.Nil)
		if err == nil {
			t.Errorf("Expected error when agentUserID is uuid.Nil")
		}
	})

	t.Run("SupportLogin fails with malformed token", func(t *testing.T) {
		_, _, err := svc.SupportLogin(context.Background(), "invalid-token-without-underscore", uuid.Must(uuid.NewV7()))
		if err == nil {
			t.Errorf("Expected error for malformed token format")
		}
	})
}

func TestGrantSupportServiceLifecycle(t *testing.T) {
	ctx := context.Background()

	// Initialize test RSA keys
	if err := security.SetupTestRSAKeys(); err != nil {
		t.Fatalf("Failed to setup RSA keys for testing: %v", err)
	}

	// Open in-memory SQLite database with foreign keys enabled
	db, err := sql.Open("sqlite", "file:grantsupport_svc_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Tier 1: Admin Creates Support Grant
	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected non-empty raw grant token")
	}

	// Tier 2: Agent Logs in via Support Grant Token
	returnedInstID, jwtToken, err := svc.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}
	if returnedInstID != instID {
		t.Fatalf("Expected institution ID %s, got %s", instID, returnedInstID)
	}
	if jwtToken == "" {
		t.Fatal("Expected non-empty JWT token")
	}

	// Verify Issued JWT claims
	claims, err := security.VerifyJWT(jwtToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claims.InstitutionID != instID.String() || claims.UserID != agentID.String() || claims.Role != "SUPPORT_AGENT" {
		t.Fatalf("Unexpected JWT claims: %+v", claims)
	}

	// Replay attempt on same rawToken fails (single-use consumption invariant)
	_, _, err = svc.SupportLogin(ctx, rawToken, agentID)
	if err != service.ErrSupportGrantInvalid {
		t.Fatalf("Expected second login on consumed grant to fail with ErrSupportGrantInvalid, got: %v", err)
	}

	// Test Revocation
	rawToken2, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant 2 failed: %v", err)
	}

	if err := svc.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("RevokeSupportGrant failed: %v", err)
	}

	// Login after revocation fails
	_, _, err = svc.SupportLogin(ctx, rawToken2, agentID)
	if err != service.ErrSupportGrantInvalid {
		t.Fatalf("Expected login on revoked grant to fail, got: %v", err)
	}
}

func TestConcurrentSupportLoginRace(t *testing.T) {
	ctx := context.Background()

	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_login_race?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()

	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	const concurrency = 50
	var successCount int64
	var failCount int64

	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		workerAgentID := uuid.New()
		go func(agentID uuid.UUID) {
			<-startCh
			_, _, err := svc.SupportLogin(context.Background(), rawToken, agentID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			doneCh <- struct{}{}
		}(workerAgentID)
	}

	close(startCh)

	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	if successCount != 1 {
		t.Fatalf("Expected EXACTLY 1 successful login among 50 concurrent workers, got: %d", successCount)
	}
	if failCount != 49 {
		t.Fatalf("Expected EXACTLY 49 failed logins among 50 concurrent workers, got: %d", failCount)
	}
}

func TestConcurrentSupportLoginRace_100Workers(t *testing.T) {
	ctx := context.Background()

	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_login_100race_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()

	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	const concurrency = 100
	var successCount int64
	var failCount int64

	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		workerAgentID := uuid.New()
		go func(agentID uuid.UUID) {
			<-startCh
			_, _, err := svc.SupportLogin(context.Background(), rawToken, agentID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			doneCh <- struct{}{}
		}(workerAgentID)
	}

	close(startCh)

	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	if successCount != 1 {
		t.Fatalf("Expected EXACTLY 1 successful login among 100 concurrent workers, got: %d", successCount)
	}
	if failCount != 99 {
		t.Fatalf("Expected EXACTLY 99 failed logins among 100 concurrent workers, got: %d", failCount)
	}
}

func TestScopedSupportGrantAndJWT(t *testing.T) {
	ctx := context.Background()

	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_scoped_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Create grant with specific scope "BILLING_ONLY" and whitelisted IP
	rawToken, err := svc.CreateSupportGrantScoped(ctx, instID, adminID, 60, "BILLING_ONLY", []string{"192.168.1.100"})
	if err != nil {
		t.Fatalf("CreateSupportGrantScoped failed: %v", err)
	}

	// Login with matching whitelisted IP and inspect JWT claims
	_, jwtToken, err := svc.SupportLogin(ctx, rawToken, agentID, "192.168.1.100")
	if err != nil {
		t.Fatalf("SupportLogin failed with valid IP: %v", err)
	}

	claims, err := security.VerifyJWT(jwtToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	if claims.Scope != "BILLING_ONLY" {
		t.Fatalf("Expected claims.Scope = BILLING_ONLY, got: %s", claims.Scope)
	}
}

func TestSupportLoginIPWhitelistEnforcement(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_ip_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()
	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// 1. Create grant with CIDR subnet restriction
	rawToken, err := svc.CreateSupportGrantScoped(ctx, instID, adminID, 60, "FULL_ACCESS", []string{"192.168.1.0/24", "10.10.0.50"})
	if err != nil {
		t.Fatalf("CreateSupportGrantScoped failed: %v", err)
	}

	// 2. Login from unlisted IP must FAIL with ErrSupportGrantInvalid
	_, _, err = svc.SupportLogin(ctx, rawToken, agentID, "172.16.0.99")
	if err == nil {
		t.Fatal("Expected SupportLogin to fail for non-whitelisted client IP")
	}

	// 3. Login with empty client IP must FAIL
	_, _, err = svc.SupportLogin(ctx, rawToken, agentID, "")
	if err == nil {
		t.Fatal("Expected SupportLogin to fail for empty client IP when whitelist is configured")
	}

	// 4. Login from allowed CIDR subnet (192.168.1.42) must SUCCEED
	_, jwtToken, err := svc.SupportLogin(ctx, rawToken, agentID, "192.168.1.42")
	if err != nil {
		t.Fatalf("Expected SupportLogin to succeed from whitelisted CIDR subnet: %v", err)
	}
	if jwtToken == "" {
		t.Fatal("Expected valid JWT token from successful login")
	}

	// 5. Verify audit event was logged for the rejected IP
	events, err := auditRepo.GetAuditEventsByInstitution(ctx, instID, 10, 0)
	if err != nil {
		t.Fatalf("Failed to query audit events: %v", err)
	}

	foundRejected := false
	for _, ev := range events {
		if ev.EventType == "SUPPORT_LOGIN_IP_REJECTED" {
			foundRejected = true
			break
		}
	}
	if !foundRejected {
		t.Error("Expected SUPPORT_LOGIN_IP_REJECTED audit event in audit log")
	}
}

func TestSupportLoginInstitutionMismatch(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_inst_mismatch_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()
	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instA := uuid.New()
	instB := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// 1. Craft a token claiming to belong to instB
	tokenBytes := []byte("01234567890123456789012345678901")
	tamperedToken := fmt.Sprintf("%s_%s", instB.String(), hex.EncodeToString(tokenBytes))
	h := sha256.Sum256([]byte(tamperedToken))
	tokenHash := hex.EncodeToString(h[:])

	// 2. Insert grant record assigned to instA with the hash of the tampered token
	grantInput := &domain.CreateSupportGrantInput{
		InstitutionID: instA,
		GrantedByID:   adminID,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(60 * time.Minute),
		Scope:         "FULL_ACCESS",
	}
	_, err = supportGrantRepo.CreateSupportGrant(ctx, grantInput)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	// 3. SupportLogin with tampered token must FAIL with ErrSupportGrantInvalid
	_, _, err = svc.SupportLogin(ctx, tamperedToken, agentID)
	if err != service.ErrSupportGrantInvalid {
		t.Fatalf("Expected ErrSupportGrantInvalid on institution mismatch, got: %v", err)
	}

	// 4. Verify audit event SUPPORT_LOGIN_INSTITUTION_MISMATCH was logged for instA
	events, err := auditRepo.GetAuditEventsByInstitution(ctx, instA, 10, 0)
	if err != nil {
		t.Fatalf("Failed to query audit events: %v", err)
	}

	foundMismatchEvent := false
	for _, ev := range events {
		if ev.EventType == "SUPPORT_LOGIN_INSTITUTION_MISMATCH" {
			foundMismatchEvent = true
			break
		}
	}
	if !foundMismatchEvent {
		t.Error("Expected SUPPORT_LOGIN_INSTITUTION_MISMATCH event in audit log for institution A")
	}
}
