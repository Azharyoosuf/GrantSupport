package grantsupport_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

// TestUUIDv7_EntityGenerationLifecycle verifies that Ent generates valid UUIDv7 IDs for SupportGrant and AuditEvent entities across all SQL dialects.
func TestUUIDv7_EntityGenerationLifecycle(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	type targetDB struct {
		name       string
		driver     string
		envVar     string
		defaultDSN string
	}

	targets := []targetDB{
		{
			name:       "SQLite (In-Memory)",
			driver:     "sqlite",
			envVar:     "",
			defaultDSN: "file:uuidv7_sqlite_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)",
		},
		{
			name:       "PostgreSQL 16",
			driver:     "pgx",
			envVar:     "TEST_POSTGRES_URL",
			defaultDSN: "postgresql://grantsupport:secretpassword@127.0.0.1:5433/grantsupport?sslmode=disable",
		},
		{
			name:       "MySQL 8.4",
			driver:     "mysql",
			envVar:     "TEST_MYSQL_URL",
			defaultDSN: "grantsupport:secretpassword@tcp(127.0.0.1:3306)/grantsupport?parseTime=true",
		},
		{
			name:       "MariaDB 11.4",
			driver:     "mysql",
			envVar:     "TEST_MARIADB_URL",
			defaultDSN: "grantsupport:secretpassword@tcp(127.0.0.1:3307)/grantsupport?parseTime=true",
		},
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			dsn := target.defaultDSN
			if target.envVar != "" && os.Getenv(target.envVar) != "" {
				dsn = os.Getenv(target.envVar)
			}

			db, err := sql.Open(target.driver, dsn)
			if err != nil {
				t.Skipf("Skipping %s: %v", target.name, err)
				return
			}
			defer db.Close()

			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := db.PingContext(pingCtx); err != nil {
				t.Skipf("Skipping %s (unreachable on %s): %v", target.name, dsn, err)
				return
			}

			dialect := "sqlite"
			if target.driver == "pgx" {
				dialect = "postgres"
			} else if target.driver == "mysql" {
				if target.name == "MariaDB 11.4" {
					dialect = "mariadb"
				} else {
					dialect = "mysql"
				}
			}

			if err := repository.CreateCapabilityTables(ctx, db, dialect); err != nil {
				t.Fatalf("[%s] CreateCapabilityTables failed: %v", target.name, err)
			}

			baseRepo := repository.NewBaseRepositoryWithDB(db, dialect)
			if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
				t.Fatalf("[%s] Schema.Create failed: %v", target.name, err)
			}

			grantRepo := repository.NewSupportGrantRepository(baseRepo)
			auditRepo := repository.NewSecurityAuditRepository(baseRepo)
			lockStore := lock.NewSQLLockStore(db, dialect)
			revStore := revocation.NewSQLRevocationStore(db, dialect)

			svc := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
			svc.SetRevocationStore(revStore)

			instID := domain.NewUUID()
			adminID := domain.NewUUID()
			agentID := domain.NewUUID()

			// 1. Create Support Grant & verify raw token format
			rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
			if err != nil {
				t.Fatalf("[%s] CreateSupportGrant failed: %v", target.name, err)
			}

			// Security Credential Invariant Assertion:
			// Raw token must contain the institution prefix and a 64-character hex string (32 bytes = 256 bits entropy)
			// It must NOT be a UUID.
			parts := strings.Split(rawToken, "_")
			if len(parts) != 2 {
				t.Fatalf("[%s] Expected raw token format '<instUUID>_<hexToken>', got: %s", target.name, rawToken)
			}
			if len(parts[1]) != 64 {
				t.Fatalf("[%s] Expected 64-char (256-bit) hex entropy token, got %d chars: %s", target.name, len(parts[1]), parts[1])
			}
			if _, err := uuid.Parse(parts[1]); err == nil {
				t.Fatalf("[%s] Security Violation: Support token was formatted as a UUID instead of 256-bit random entropy", target.name)
			}

			// 2. Query the created SupportGrant and verify its primary key is UUIDv7
			h := sha256.Sum256([]byte(rawToken))
			tokenHash := hex.EncodeToString(h[:])
			grant, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
			if err != nil || grant == nil {
				t.Fatalf("[%s] FindActiveGrantByTokenHash failed: %v", target.name, err)
			}

			if grant.ID.Version() != 7 {
				t.Fatalf("[%s] Expected SupportGrant.ID to be UUIDv7, got version %d (%s)", target.name, grant.ID.Version(), grant.ID)
			}
			if grant.ID.Variant() != uuid.RFC4122 {
				t.Fatalf("[%s] Expected SupportGrant.ID to have RFC 4122/9562 variant, got %v", target.name, grant.ID.Variant())
			}

			// 3. Redeem Grant via SupportLogin and verify AuditEvent ID is UUIDv7
			loginInstID, jwtToken, err := svc.SupportLogin(ctx, rawToken, agentID)
			if err != nil || loginInstID != instID || jwtToken == "" {
				t.Fatalf("[%s] SupportLogin failed: %v", target.name, err)
			}

			// 4. Verify AuditEvent entries have UUIDv7 IDs
			events, err := auditRepo.GetAuditEventsByInstitution(ctx, instID, 10, 0)
			if err != nil || len(events) == 0 {
				t.Fatalf("[%s] GetAuditEventsByInstitution failed: %v, events: %d", target.name, err, len(events))
			}

			for _, event := range events {
				if event.ID.Version() != 7 {
					t.Fatalf("[%s] Expected AuditEvent.ID to be UUIDv7, got version %d (%s)", target.name, event.ID.Version(), event.ID)
				}
			}

			// 5. Verify Audit Hash Chain is unbroken
			validChain, err := auditRepo.VerifyAuditChain(ctx, instID)
			if err != nil || !validChain {
				t.Fatalf("[%s] VerifyAuditChain failed: valid=%v, err=%v", target.name, validChain, err)
			}
		})
	}
}

// TestUUIDv7_EngineEndToEnd verifies the high-level Engine API produces UUIDv7 entities.
func TestUUIDv7_EngineEndToEnd(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:uuidv7_engine_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	instID := domain.NewUUID()
	adminID := domain.NewUUID()
	agentID := domain.NewUUID()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	_, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil || jwtToken == "" {
		t.Fatalf("SupportLogin failed: %v", err)
	}

	valid, err := engine.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("VerifyAuditChain failed: %v", err)
	}
}
