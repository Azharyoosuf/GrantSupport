package repository_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/replay"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
)

// runDatabaseComplianceSuite executes a standardized matrix of capability tests against any supported SQL database driver.
func runDatabaseComplianceSuite(t *testing.T, dialectName string, db *sql.DB) {
	ctx := context.Background()

	baseRepo := repository.NewBaseRepositoryWithDB(db, dialectName)
	client, err := baseRepo.GetClient(ctx)
	if err != nil {
		t.Fatalf("[%s] Failed to get Ent client: %v", dialectName, err)
	}

	// 1. Schema Creation
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatalf("[%s] Schema creation failed: %v", dialectName, err)
	}

	// Create capability tables for lock, replay, revocation
	if err := repository.CreateCapabilityTables(ctx, db, dialectName); err != nil {
		t.Fatalf("[%s] Capability DDL execution failed: %v", dialectName, err)
	}

	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewSQLLockStore(db, dialectName)
	auditRepo.SetLockStore(lockStore)

	replayStore := replay.NewSQLReplayStore(db, dialectName)
	revocationStore := revocation.NewSQLRevocationStore(db, dialectName)

	instA := uuid.New()
	instB := uuid.New()
	adminA := uuid.New()
	adminB := uuid.New()

	// 2. Grant Creation & Verification
	tokenHashA := fmt.Sprintf("hash_a_%s", uuid.New().String())
	tokenHashB := fmt.Sprintf("hash_b_%s", uuid.New().String())

	grantA, err := grantRepo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID:  instA,
		GrantedByID:    adminA,
		TokenHash:      tokenHashA,
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		Scope:          "BILLING_ONLY",
		WhitelistedIPs: []string{"10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("[%s] CreateSupportGrant A failed: %v", dialectName, err)
	}
	if grantA.Scope != "BILLING_ONLY" {
		t.Fatalf("[%s] Expected scope BILLING_ONLY, got %s", dialectName, grantA.Scope)
	}

	_, err = grantRepo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID: instB,
		GrantedByID:   adminB,
		TokenHash:     tokenHashB,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		Scope:         "FULL_ACCESS",
	})
	if err != nil {
		t.Fatalf("[%s] CreateSupportGrant B failed: %v", dialectName, err)
	}

	// 3. Multi-Tenant Isolation Verification
	foundA, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHashA)
	if err != nil || foundA == nil || foundA.InstitutionID != instA {
		t.Fatalf("[%s] Tenant isolation check failed for Grant A: %+v, err: %v", dialectName, foundA, err)
	}

	foundB, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHashB)
	if err != nil || foundB == nil || foundB.InstitutionID != instB {
		t.Fatalf("[%s] Tenant isolation check failed for Grant B: %+v, err: %v", dialectName, foundB, err)
	}

	// 4. 100-Worker Atomic Single-Use Concurrency Test
	const concurrency = 100
	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)
	var successCount int64
	var failCount int64

	for i := 0; i < concurrency; i++ {
		go func() {
			<-startCh
			err := grantRepo.MarkGrantAsUsed(context.Background(), grantA.ID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			doneCh <- struct{}{}
		}()
	}

	close(startCh)
	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	if successCount != 1 {
		t.Fatalf("[%s] Expected EXACTLY 1 successful consumption among %d workers, got: %d", dialectName, concurrency, successCount)
	}
	if failCount != int64(concurrency-1) {
		t.Fatalf("[%s] Expected EXACTLY %d failed consumptions, got: %d", dialectName, concurrency-1, failCount)
	}

	// 5. 100-Worker SQLLockStore Concurrency, Ownership & Expiry Takeover Test
	lockKey := fmt.Sprintf("lock:compliance:%s", instA.String())
	lockStartCh := make(chan struct{})
	lockDoneCh := make(chan string, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			<-lockStartCh
			token, err := lockStore.Acquire(context.Background(), lockKey, 2*time.Second)
			if err == nil {
				lockDoneCh <- token
			} else {
				lockDoneCh <- ""
			}
		}()
	}

	close(lockStartCh)
	var winnerToken string
	var lockWinners int
	for i := 0; i < concurrency; i++ {
		tok := <-lockDoneCh
		if tok != "" {
			winnerToken = tok
			lockWinners++
		}
	}

	if lockWinners != 1 {
		t.Fatalf("[%s] Expected EXACTLY 1 lock winner among %d concurrent attempts, got: %d", dialectName, concurrency, lockWinners)
	}

	// Test non-owner release fails to release
	_ = lockStore.Release(ctx, lockKey, "fake_non_owner_token")
	_, err = lockStore.Acquire(ctx, lockKey, 2*time.Second)
	if err != ports.ErrLockBusy {
		t.Fatalf("[%s] Expected lock to remain busy after fake release, got: %v", dialectName, err)
	}

	// Test valid owner release succeeds
	if err := lockStore.Release(ctx, lockKey, winnerToken); err != nil {
		t.Fatalf("[%s] Valid owner release failed: %v", dialectName, err)
	}

	// Test lock lease expiration & takeover
	shortLockKey := fmt.Sprintf("lock:expire:%s", instA.String())
	tok1, err := lockStore.Acquire(ctx, shortLockKey, 50*time.Millisecond)
	if err != nil || tok1 == "" {
		t.Fatalf("[%s] Short lock acquire failed: %v", dialectName, err)
	}
	time.Sleep(70 * time.Millisecond) // Wait for lease to expire
	tok2, err := lockStore.Acquire(ctx, shortLockKey, 1*time.Second)
	if err != nil || tok2 == "" {
		t.Fatalf("[%s] Expired lock takeover failed: %v", dialectName, err)
	}
	_ = lockStore.Release(ctx, shortLockKey, tok2)

	// 6. SQL Replay Store Nonce Uniqueness Test
	nonce := fmt.Sprintf("nonce_%s", uuid.New().String())
	valid, err := replayStore.CheckAndSet(ctx, "key1", nonce, 5*time.Minute)
	if err != nil || !valid {
		t.Fatalf("[%s] Initial nonce CheckAndSet failed: valid=%v, err=%v", dialectName, valid, err)
	}
	valid, err = replayStore.CheckAndSet(ctx, "key1", nonce, 5*time.Minute)
	if valid || (err != nil && err != ports.ErrReplayDetected) {
		t.Fatalf("[%s] Reused nonce expected valid=false/ErrReplayDetected, got valid=%v, err=%v", dialectName, valid, err)
	}

	// 7. SQL Revocation Store Test
	userRevokeID := uuid.New().String()
	revoked, err := revocationStore.IsTokenRevoked(ctx, instA.String(), userRevokeID, 1)
	if err != nil || revoked {
		t.Fatalf("[%s] Expected user not revoked, got revoked=%v, err=%v", dialectName, revoked, err)
	}

	if err := revocationStore.RevokeUserSessions(ctx, instA.String(), userRevokeID, 2); err != nil {
		t.Fatalf("[%s] RevokeUserSessions failed: %v", dialectName, err)
	}

	revoked, err = revocationStore.IsTokenRevoked(ctx, instA.String(), userRevokeID, 1)
	if err != nil || !revoked {
		t.Fatalf("[%s] Expected token version 1 to be revoked after version 2 bump, got revoked=%v", dialectName, revoked)
	}

	// 8. Cryptographic Audit Hash Chain & Concurrent Serialization Test
	const auditConcurrency = 25
	var wg sync.WaitGroup
	wg.Add(auditConcurrency)

	for i := 1; i <= auditConcurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			_, logErr := auditRepo.LogSecurityEvent(ctx, instA, adminA, "AUDIT_EVENT", fmt.Sprintf("Concurrent event %d with email test%d@company.com", idx, idx), nil)
			if logErr != nil {
				t.Errorf("[%s] Concurrent LogSecurityEvent %d failed: %v", dialectName, idx, logErr)
			}
		}(i)
	}
	wg.Wait()

	validChain, err := auditRepo.VerifyAuditChain(ctx, instA)
	if err != nil || !validChain {
		t.Fatalf("[%s] Concurrent audit chain verification failed: valid=%v, err=%v", dialectName, validChain, err)
	}

	// 9. Tenant Revocation Isolation
	if err := grantRepo.RevokeAllGrantsForInstitution(ctx, instA); err != nil {
		t.Fatalf("[%s] RevokeAllGrantsForInstitution failed: %v", dialectName, err)
	}
	activeA, _ := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHashA)
	if activeA != nil {
		t.Fatalf("[%s] Grant A should be revoked and unfindable as active", dialectName)
	}
	activeB, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHashB)
	if err != nil || activeB == nil {
		t.Fatalf("[%s] Grant B in Tenant B should remain active after Tenant A revocation", dialectName)
	}
}

// TestDatabaseComplianceSuite_SQLite runs the compliance matrix against in-memory SQLite.
func TestDatabaseComplianceSuite_SQLite(t *testing.T) {
	db, err := sql.Open("sqlite", "file:compliance_sqlite_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	runDatabaseComplianceSuite(t, "sqlite", db)
}

// TestDatabaseComplianceSuite_PostgreSQL runs when TEST_POSTGRES_URL environment variable is provided.
func TestDatabaseComplianceSuite_PostgreSQL(t *testing.T) {
	connStr := os.Getenv("TEST_POSTGRES_URL")
	if connStr == "" {
		t.Skip("Skipping PostgreSQL compliance test: TEST_POSTGRES_URL not configured")
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	runDatabaseComplianceSuite(t, "postgres", db)
}

// TestDatabaseComplianceSuite_MySQL runs when TEST_MYSQL_URL environment variable is provided.
func TestDatabaseComplianceSuite_MySQL(t *testing.T) {
	connStr := os.Getenv("TEST_MYSQL_URL")
	if connStr == "" {
		t.Skip("Skipping MySQL compliance test: TEST_MYSQL_URL not configured")
	}

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to MySQL: %v", err)
	}
	defer db.Close()

	runDatabaseComplianceSuite(t, "mysql", db)
}

// TestDatabaseComplianceSuite_MariaDB runs when TEST_MARIADB_URL environment variable is provided.
func TestDatabaseComplianceSuite_MariaDB(t *testing.T) {
	connStr := os.Getenv("TEST_MARIADB_URL")
	if connStr == "" {
		t.Skip("Skipping MariaDB compliance test: TEST_MARIADB_URL not configured")
	}

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to MariaDB: %v", err)
	}
	defer db.Close()

	runDatabaseComplianceSuite(t, "mariadb", db)
}
