package grantsupport_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
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
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

// TestDatabaseUpgrade_SchemaMigration runs a comprehensive existing-database upgrade test on SQLite.
func TestDatabaseUpgrade_SchemaMigration(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:test_legacy_upgrade?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	// 1. Create OLD schema (version 000001 without used_by_id)
	oldSchema := `
	CREATE TABLE gs_support_grants (
		id TEXT PRIMARY KEY,
		institution_id TEXT NOT NULL,
		granted_by_id TEXT NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at DATETIME NOT NULL,
		is_used BOOLEAN NOT NULL DEFAULT FALSE,
		used_at DATETIME,
		scope TEXT NOT NULL DEFAULT 'FULL_ACCESS',
		whitelisted_ips TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX idx_gs_support_grants_inst_exp ON gs_support_grants (institution_id, expires_at);
	CREATE INDEX idx_gs_support_grants_token_hash ON gs_support_grants (token_hash);

	CREATE TABLE gs_audit_events (
		id TEXT PRIMARY KEY,
		institution_id TEXT NOT NULL,
		actor_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		description TEXT,
		hash_chain TEXT,
		signature TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX idx_gs_audit_events_inst_created ON gs_audit_events (institution_id, created_at);

	CREATE TABLE gs_locks (
		lock_key TEXT PRIMARY KEY,
		owner_token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		acquired_at DATETIME NOT NULL
	);
	CREATE TABLE gs_replays (
		nonce_key TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);
	CREATE TABLE gs_revocations (
		institution_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		token_version INTEGER NOT NULL DEFAULT 1,
		revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (institution_id, user_id)
	);
	`
	if _, err := db.ExecContext(ctx, oldSchema); err != nil {
		t.Fatalf("Failed to create old schema: %v", err)
	}

	// 2. Insert representative legacy records into old schema
	instA := uuid.New()
	instB := uuid.New()
	adminA := uuid.New()
	adminB := uuid.New()

	// Legacy Record 1: Unused active grant
	tokenHash1 := fmt.Sprintf("%x", sha256.Sum256([]byte("legacy_token_1")))
	grantID1 := uuid.New().String()
	_, err = db.ExecContext(ctx, `
		INSERT INTO gs_support_grants (id, institution_id, granted_by_id, token_hash, expires_at, is_used, created_at)
		VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
	`, grantID1, instA.String(), adminA.String(), tokenHash1, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to insert legacy grant 1: %v", err)
	}

	// Legacy Record 2: Expired grant
	tokenHash2 := fmt.Sprintf("%x", sha256.Sum256([]byte("legacy_token_2")))
	grantID2 := uuid.New().String()
	_, err = db.ExecContext(ctx, `
		INSERT INTO gs_support_grants (id, institution_id, granted_by_id, token_hash, expires_at, is_used, created_at)
		VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
	`, grantID2, instA.String(), adminA.String(), tokenHash2, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to insert legacy grant 2: %v", err)
	}

	// Legacy Record 3: Already used grant (before used_by_id existed)
	tokenHash3 := fmt.Sprintf("%x", sha256.Sum256([]byte("legacy_token_3")))
	grantID3 := uuid.New().String()
	_, err = db.ExecContext(ctx, `
		INSERT INTO gs_support_grants (id, institution_id, granted_by_id, token_hash, expires_at, is_used, used_at, created_at)
		VALUES (?, ?, ?, ?, ?, 1, ?, CURRENT_TIMESTAMP)
	`, grantID3, instB.String(), adminB.String(), tokenHash3, time.Now().Add(1*time.Hour), time.Now().Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("Failed to insert legacy grant 3: %v", err)
	}

	// 3. Run Upgrade Migration (000002_add_used_by_id_to_support_grants)
	upgradeSQL := `
		ALTER TABLE gs_support_grants ADD COLUMN used_by_id TEXT;
		CREATE INDEX IF NOT EXISTS idx_gs_support_grants_used_by ON gs_support_grants (institution_id, used_by_id);
	`
	if _, err := db.ExecContext(ctx, upgradeSQL); err != nil {
		t.Fatalf("Upgrade migration failed: %v", err)
	}

	// 4. Verify existing rows remain intact with NULL used_by_id
	var rowCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM gs_support_grants").Scan(&rowCount); err != nil || rowCount != 3 {
		t.Fatalf("Expected 3 existing grant rows after upgrade, got: %d (err=%v)", rowCount, err)
	}

	var legacyUsedByID sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT used_by_id FROM gs_support_grants WHERE id = ?", grantID3).Scan(&legacyUsedByID); err != nil {
		t.Fatalf("Failed to query legacy grant used_by_id: %v", err)
	}
	if legacyUsedByID.Valid {
		t.Fatalf("Expected legacy used grant to have NULL used_by_id, got: %s", legacyUsedByID.String)
	}

	// 5. Initialize Engine with the upgraded database
	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine on upgraded DB failed: %v", err)
	}
	defer engine.Close()

	// 6. Create a NEW grant on the upgraded database
	agentID := uuid.New()
	newToken, err := engine.CreateSupportGrant(ctx, instA, adminA, 60, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant on upgraded DB failed: %v", err)
	}

	// 7. Redeem the NEW grant and verify used_by_id is correctly populated
	_, agentJWT, err := engine.SupportLogin(ctx, newToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin on upgraded DB failed: %v", err)
	}
	if agentJWT == "" {
		t.Fatal("Expected non-empty JWT token")
	}

	// Query DB to verify used_by_id was written
	parts := fmt.Sprintf("%x", sha256.Sum256([]byte(newToken)))
	var recordedUsedByID string
	err = db.QueryRowContext(ctx, "SELECT used_by_id FROM gs_support_grants WHERE token_hash = ?", parts).Scan(&recordedUsedByID)
	if err != nil {
		t.Fatalf("Failed to query used_by_id for new grant: %v", err)
	}
	if recordedUsedByID != agentID.String() {
		t.Fatalf("Expected used_by_id = %s, got: %s", agentID.String(), recordedUsedByID)
	}

	// 8. Revoke support and verify active session is invalidated
	if err := engine.RevokeSupportGrant(ctx, instA, adminA); err != nil {
		t.Fatalf("RevokeSupportGrant failed: %v", err)
	}

	// Verify agent token is now revoked
	claims, err := security.VerifyJWT(agentJWT)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	sqlRevStore := revocation.NewSQLRevocationStore(db, "sqlite")
	revoked, err := sqlRevStore.IsTokenRevoked(ctx, claims.InstitutionID, claims.UserID, claims.TokenVersion)
	if err != nil || !revoked {
		t.Fatalf("Expected token to be revoked on upgraded database, got revoked=%v, err=%v", revoked, err)
	}
}

// TestSessionLifecycle_FourHourBoundaryCases tests all boundary conditions around the 4-hour session window.
func TestSessionLifecycle_FourHourBoundaryCases(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:test_four_hour_boundary?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
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

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Case 1: Immediately after login -> revoke -> JWT rejected
	t.Run("Case 1: Immediately after login", func(t *testing.T) {
		token, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
		if err != nil {
			t.Fatalf("CreateSupportGrant failed: %v", err)
		}
		_, jwtToken, err := engine.SupportLogin(ctx, token, agentID)
		if err != nil {
			t.Fatalf("SupportLogin failed: %v", err)
		}

		if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
			t.Fatalf("RevokeSupportGrant failed: %v", err)
		}

		claims, _ := security.VerifyJWT(jwtToken)
		sqlRevStore := revocation.NewSQLRevocationStore(db, "sqlite")
		revoked, err := sqlRevStore.IsTokenRevoked(ctx, claims.InstitutionID, claims.UserID, claims.TokenVersion)
		if err != nil || !revoked {
			t.Fatalf("Expected immediate revocation to invalidate JWT session, got: revoked=%v, err=%v", revoked, err)
		}
	})

	// Case 2: Near 4-hour boundary (session redeemed 3h 50m ago) -> admin revokes -> session invalidated
	t.Run("Case 2: Near 4-hour boundary", func(t *testing.T) {
		agentNearExpiry := uuid.New()
		nearExpiryToken := fmt.Sprintf("%s_%s", instID.String(), hex.EncodeToString([]byte("01234567890123456789012345678901")))
		tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(nearExpiryToken)))

		// Insert grant consumed 3 hours and 50 minutes ago
		usedAt := time.Now().Add(-3*time.Hour - 50*time.Minute)
		_, err := db.ExecContext(ctx, `
			INSERT INTO gs_support_grants (id, institution_id, granted_by_id, used_by_id, token_hash, expires_at, is_used, used_at, scope, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'FULL_ACCESS', ?)
		`, uuid.New().String(), instID.String(), adminID.String(), agentNearExpiry.String(), tokenHash, time.Now().Add(1*time.Hour), usedAt, usedAt)
		if err != nil {
			t.Fatalf("Failed to insert simulated near-expiry grant: %v", err)
		}

		// Agent has JWT version 1 issued 3h 50m ago
		jwtToken, err := security.GenerateJWTWithVersion(agentNearExpiry.String(), instID.String(), "SUPPORT_AGENT", "FULL_ACCESS", 1, 10*time.Minute)
		if err != nil {
			t.Fatalf("GenerateJWTWithVersion failed: %v", err)
		}

		// Admin revokes support
		if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
			t.Fatalf("RevokeSupportGrant failed: %v", err)
		}

		// Session was within 4h window, so RevokeAllGrantsForInstitution must have found it and bumped token version
		claims, _ := security.VerifyJWT(jwtToken)
		sqlRevStore := revocation.NewSQLRevocationStore(db, "sqlite")
		revoked, err := sqlRevStore.IsTokenRevoked(ctx, claims.InstitutionID, claims.UserID, claims.TokenVersion)
		if err != nil || !revoked {
			t.Fatalf("Expected near-expiry session to be revoked, got: revoked=%v, err=%v", revoked, err)
		}
	})

	// Case 3: Exactly at/after natural expiration -> rejected by VerifyJWT
	t.Run("Case 3: Natural JWT expiration rejects without revocation", func(t *testing.T) {
		expiredJWT, err := security.GenerateJWTWithVersion(agentID.String(), instID.String(), "SUPPORT_AGENT", "FULL_ACCESS", 1, -1*time.Minute)
		if err != nil {
			t.Fatalf("GenerateJWTWithVersion failed: %v", err)
		}

		_, err = security.VerifyJWT(expiredJWT)
		if err == nil {
			t.Fatal("Expected expired JWT to fail verification naturally")
		}
	})

	// Case 4: More than 4 hours after redemption -> old grant not treated as active session
	t.Run("Case 4: Grant used > 4 hours ago", func(t *testing.T) {
		oldAgentID := uuid.New()
		oldToken := fmt.Sprintf("%s_%s", instID.String(), hex.EncodeToString([]byte("oldoldoldoldoldoldoldoldoldold12")))
		tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte(oldToken)))

		// Insert grant consumed 5 hours ago
		usedAt := time.Now().Add(-5 * time.Hour)
		_, err := db.ExecContext(ctx, `
			INSERT INTO gs_support_grants (id, institution_id, granted_by_id, used_by_id, token_hash, expires_at, is_used, used_at, scope, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'FULL_ACCESS', ?)
		`, uuid.New().String(), instID.String(), adminID.String(), oldAgentID.String(), tokenHash, time.Now().Add(-1*time.Hour), usedAt, usedAt)
		if err != nil {
			t.Fatalf("Failed to insert 5h old grant: %v", err)
		}

		// When admin revokes, oldAgentID should not have an unnecessary version bump because its session is long expired
		if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
			t.Fatalf("RevokeSupportGrant failed: %v", err)
		}
	})

	// Case 5: Session Reuse (Agent redeems old grant, later redeems new grant)
	t.Run("Case 5: Session reuse across grants", func(t *testing.T) {
		reusedAgentID := uuid.New()

		// 1. Agent claims first grant
		token1, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
		if err != nil {
			t.Fatalf("CreateSupportGrant 1 failed: %v", err)
		}
		_, jwt1, err := engine.SupportLogin(ctx, token1, reusedAgentID)
		if err != nil {
			t.Fatalf("SupportLogin 1 failed: %v", err)
		}

		// 2. Admin revokes -> jwt1 invalidated
		if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
			t.Fatalf("RevokeSupportGrant 1 failed: %v", err)
		}

		claims1, _ := security.VerifyJWT(jwt1)
		sqlRevStore := revocation.NewSQLRevocationStore(db, "sqlite")
		revoked, _ := sqlRevStore.IsTokenRevoked(ctx, claims1.InstitutionID, claims1.UserID, claims1.TokenVersion)
		if !revoked {
			t.Fatal("Expected jwt1 to be revoked")
		}

		// 3. Later, Admin creates a NEW grant for the same institution
		token2, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
		if err != nil {
			t.Fatalf("CreateSupportGrant 2 failed: %v", err)
		}

		// 4. Same Agent logs in with the NEW grant
		_, jwt2, err := engine.SupportLogin(ctx, token2, reusedAgentID)
		if err != nil {
			t.Fatalf("SupportLogin 2 failed: %v", err)
		}

		// 5. Verify jwt2 has incremented token version and is VALID
		claims2, err := security.VerifyJWT(jwt2)
		if err != nil {
			t.Fatalf("VerifyJWT for jwt2 failed: %v", err)
		}
		if claims2.TokenVersion <= claims1.TokenVersion {
			t.Fatalf("Expected new token version %d > old version %d", claims2.TokenVersion, claims1.TokenVersion)
		}

		revoked2, err := sqlRevStore.IsTokenRevoked(ctx, claims2.InstitutionID, claims2.UserID, claims2.TokenVersion)
		if err != nil || revoked2 {
			t.Fatalf("Expected jwt2 to be valid, got revoked=%v, err=%v", revoked2, err)
		}

		// 6. Admin revokes again -> jwt2 is now revoked
		if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
			t.Fatalf("RevokeSupportGrant 2 failed: %v", err)
		}

		revoked2After, err := sqlRevStore.IsTokenRevoked(ctx, claims2.InstitutionID, claims2.UserID, claims2.TokenVersion)
		if err != nil || !revoked2After {
			t.Fatalf("Expected jwt2 to be revoked after second revocation, got revoked=%v, err=%v", revoked2After, err)
		}
	})
}

// TestCrossDialectLiveDatabaseUpgrade runs live database upgrade and fresh installation verification against PostgreSQL, MySQL, and MariaDB if configured.
func TestCrossDialectLiveDatabaseUpgrade(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	dialects := []struct {
		name       string
		driver     string
		envVar     string
		defaultDSN string
	}{
		{
			name:       "postgres",
			driver:     "pgx",
			envVar:     "TEST_POSTGRES_URL",
			defaultDSN: "postgresql://grantsupport:secretpassword@127.0.0.1:5433/grantsupport?sslmode=disable",
		},
		{
			name:       "mysql",
			driver:     "mysql",
			envVar:     "TEST_MYSQL_URL",
			defaultDSN: "grantsupport:secretpassword@tcp(127.0.0.1:3306)/grantsupport?parseTime=true",
		},
		{
			name:       "mariadb",
			driver:     "mysql",
			envVar:     "TEST_MARIADB_URL",
			defaultDSN: "grantsupport:secretpassword@tcp(127.0.0.1:3307)/grantsupport?parseTime=true",
		},
	}

	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			dsn := os.Getenv(d.envVar)
			if dsn == "" {
				dsn = d.defaultDSN
			}

			db, err := sql.Open(d.driver, dsn)
			if err != nil {
				t.Skipf("Skipping %s live test: %v", d.name, err)
				return
			}
			defer db.Close()

			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := db.PingContext(pingCtx); err != nil {
				t.Skipf("Skipping %s live test (database unreachable): %v", d.name, err)
				return
			}

			// Clean/Prepare capability tables
			if err := repository.CreateCapabilityTables(ctx, db, d.name); err != nil {
				t.Fatalf("[%s] CreateCapabilityTables failed: %v", d.name, err)
			}

			baseRepo := repository.NewBaseRepositoryWithDB(db, d.name)
			if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
				t.Fatalf("[%s] Ent Schema.Create failed: %v", d.name, err)
			}

			grantRepo := repository.NewSupportGrantRepository(baseRepo)
			auditRepo := repository.NewSecurityAuditRepository(baseRepo)
			lockStore := lock.NewSQLLockStore(db, d.name)
			revocationStore := revocation.NewSQLRevocationStore(db, d.name)

			svc := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
			svc.SetRevocationStore(revocationStore)

			instID := uuid.New()
			adminID := uuid.New()
			agentID := uuid.New()

			// 1. Create grant
			token, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
			if err != nil {
				t.Fatalf("[%s] CreateSupportGrant failed: %v", d.name, err)
			}

			// 2. Redeem grant -> sets used_by_id
			_, agentJWT, err := svc.SupportLogin(ctx, token, agentID)
			if err != nil {
				t.Fatalf("[%s] SupportLogin failed: %v", d.name, err)
			}

			// 3. Verify JWT is active
			claims, err := security.VerifyJWT(agentJWT)
			if err != nil {
				t.Fatalf("[%s] VerifyJWT failed: %v", d.name, err)
			}
			revoked, err := revocationStore.IsTokenRevoked(ctx, claims.InstitutionID, claims.UserID, claims.TokenVersion)
			if err != nil || revoked {
				t.Fatalf("[%s] Expected active session before revocation, got revoked=%v, err=%v", d.name, revoked, err)
			}

			// 4. Admin revokes
			if err := svc.RevokeSupportGrant(ctx, instID, adminID); err != nil {
				t.Fatalf("[%s] RevokeSupportGrant failed: %v", d.name, err)
			}

			// 5. Verify agent JWT is revoked
			revoked, err = revocationStore.IsTokenRevoked(ctx, claims.InstitutionID, claims.UserID, claims.TokenVersion)
			if err != nil || !revoked {
				t.Fatalf("[%s] Expected session to be revoked after admin revocation, got revoked=%v, err=%v", d.name, revoked, err)
			}
		})
	}
}

// execSQLStatements strips comment lines, splits a migration script by semicolons, and executes each non-empty statement.
func execSQLStatements(ctx context.Context, db *sql.DB, script []byte) error {
	var nonCommentLines []string
	for _, line := range strings.Split(string(script), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		nonCommentLines = append(nonCommentLines, line)
	}
	cleanedScript := strings.Join(nonCommentLines, "\n")
	for _, rawStmt := range strings.Split(cleanedScript, ";") {
		stmt := strings.TrimSpace(rawStmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("statement failed (%s): %w", stmt, err)
		}
	}
	return nil
}

// runDialectPhysicalMigrationsTest verifies 000001-000004 on a fresh DB (including 000004 down/up reversibility)
// and verifies applying 000004 on a DB that already has data in gs_access_requests.
func runDialectPhysicalMigrationsTest(t *testing.T, ctx context.Context, dialect string, openFreshDB func(t *testing.T, suffix string) *sql.DB) {
	t.Helper()

	readMig := func(name string) []byte {
		t.Helper()
		path := fmt.Sprintf("../../migrations/%s/%s", dialect, name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("[%s] Failed to read migration %s: %v", dialect, path, err)
		}
		return b
	}

	up1 := readMig("000001_initial_grantsupport_schema.up.sql")
	up2 := readMig("000002_add_used_by_id_to_support_grants.up.sql")
	up3 := readMig("000003_add_access_requests.up.sql")
	up4 := readMig("000004_drop_access_requests.up.sql")

	down4 := readMig("000004_drop_access_requests.down.sql")
	down3 := readMig("000003_add_access_requests.down.sql")
	down2 := readMig("000002_add_used_by_id_to_support_grants.down.sql")
	down1 := readMig("000001_initial_grantsupport_schema.down.sql")

	// Scenario 1: Apply 000001-000004 on a fresh DB, verify DOWN reversibility and Re-UP
	t.Run("FreshDB_000001_to_000004_And_Reversibility", func(t *testing.T) {
		db := openFreshDB(t, "fresh")
		defer db.Close()

		// Ensure clean state before starting
		_ = execSQLStatements(ctx, db, down3)
		_ = execSQLStatements(ctx, db, down1)

		// A. Execute UP: 1 -> 2 -> 3 -> 4 on a fresh DB
		for _, script := range [][]byte{up1, up2, up3, up4} {
			if err := execSQLStatements(ctx, db, script); err != nil {
				t.Fatalf("[%s] Fresh DB UP 000001-000004 failed: %v", dialect, err)
			}
		}

		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_support_grants").Scan(&count); err != nil {
			t.Fatalf("[%s] Expected gs_support_grants table to exist after 000001-000004 UP: %v", dialect, err)
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_audit_events").Scan(&count); err != nil {
			t.Fatalf("[%s] Expected gs_audit_events table to exist after 000001-000004 UP: %v", dialect, err)
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_access_requests").Scan(&count); err == nil {
			t.Fatalf("[%s] Expected gs_access_requests to NOT exist after 000004 UP", dialect)
		}

		// B. Execute 000004.down -> recreates empty gs_access_requests table
		if err := execSQLStatements(ctx, db, down4); err != nil {
			t.Fatalf("[%s] 000004 DOWN failed: %v", dialect, err)
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_access_requests").Scan(&count); err != nil || count != 0 {
			t.Fatalf("[%s] Expected empty gs_access_requests table after 000004 DOWN, got count=%d, err=%v", dialect, count, err)
		}

		// C. Execute remaining DOWN: 3 -> 2 -> 1
		for _, script := range [][]byte{down3, down2, down1} {
			if err := execSQLStatements(ctx, db, script); err != nil {
				t.Fatalf("[%s] DOWN 000003-000001 failed: %v", dialect, err)
			}
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_support_grants").Scan(&count); err == nil {
			t.Fatalf("[%s] Expected gs_support_grants to be dropped after full DOWN", dialect)
		}

		// D. Execute Re-UP: 1 -> 2 -> 3 -> 4
		for _, script := range [][]byte{up1, up2, up3, up4} {
			if err := execSQLStatements(ctx, db, script); err != nil {
				t.Fatalf("[%s] Re-UP 000001-000004 failed: %v", dialect, err)
			}
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_support_grants").Scan(&count); err != nil {
			t.Fatalf("[%s] Expected gs_support_grants table to exist after Re-UP: %v", dialect, err)
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_access_requests").Scan(&count); err == nil {
			t.Fatalf("[%s] Expected gs_access_requests to be dropped after Re-UP 000004", dialect)
		}
	})

	// Scenario 2: Apply 000004 on a DB that already has data in gs_access_requests
	t.Run("PopulatedDB_Apply000004_WithExistingData", func(t *testing.T) {
		db := openFreshDB(t, "populated")
		defer db.Close()

		// Ensure clean state before starting
		_ = execSQLStatements(ctx, db, down3)
		_ = execSQLStatements(ctx, db, down1)

		// 1. Apply 000001 -> 000003
		for _, script := range [][]byte{up1, up2, up3} {
			if err := execSQLStatements(ctx, db, script); err != nil {
				t.Fatalf("[%s] UP 000001-000003 failed: %v", dialect, err)
			}
		}

		// 2. Seed existing rows into gs_access_requests and gs_support_grants
		instID := uuid.New().String()
		requesterID := uuid.New().String()
		adminID := uuid.New().String()
		reqID1 := uuid.New().String()
		reqID2 := uuid.New().String()
		grantID := uuid.New().String()
		tokenHash := fmt.Sprintf("%x", sha256.Sum256([]byte("existing_grant_"+grantID)))
		expiresAt := time.Now().UTC().Add(2 * time.Hour).Format("2006-01-02 15:04:05")

		insertGrantSQL := fmt.Sprintf(
			"INSERT INTO gs_support_grants (id, institution_id, granted_by_id, token_hash, expires_at, scope) VALUES ('%s', '%s', '%s', '%s', '%s', 'FULL_ACCESS')",
			grantID, instID, adminID, tokenHash, expiresAt,
		)
		if _, err := db.ExecContext(ctx, insertGrantSQL); err != nil {
			t.Fatalf("[%s] Failed to insert existing grant row: %v", dialect, err)
		}

		insertReq1SQL := fmt.Sprintf(
			"INSERT INTO gs_access_requests (id, institution_id, requester_id, target_service, reason, requested_duration_minutes, requested_scope, status, expires_at) VALUES ('%s', '%s', '%s', 'billing', 'Investigate invoice discrepancy', 60, 'FULL_ACCESS', 'PENDING', '%s')",
			reqID1, instID, requesterID, expiresAt,
		)
		insertReq2SQL := fmt.Sprintf(
			"INSERT INTO gs_access_requests (id, institution_id, requester_id, target_service, reason, requested_duration_minutes, approved_duration_minutes, requested_scope, approved_scope, status, expires_at, approved_by_id, support_grant_id) VALUES ('%s', '%s', '%s', 'Core API', 'Customer approved ticket', 45, 45, 'FULL_ACCESS', 'FULL_ACCESS', 'APPROVED', '%s', '%s', '%s')",
			reqID2, instID, requesterID, expiresAt, adminID, grantID,
		)
		for _, stmt := range []string{insertReq1SQL, insertReq2SQL} {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("[%s] Failed to insert existing row into gs_access_requests: %v", dialect, err)
			}
		}

		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_access_requests").Scan(&count); err != nil || count != 2 {
			t.Fatalf("[%s] Expected 2 rows in gs_access_requests before 000004, got count=%d, err=%v", dialect, count, err)
		}

		// 3. Apply 000004.up on the populated database
		if err := execSQLStatements(ctx, db, up4); err != nil {
			t.Fatalf("[%s] Applying 000004.up on populated gs_access_requests failed: %v", dialect, err)
		}

		// 4. Verify gs_access_requests is dropped and gs_support_grants data is preserved
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_access_requests").Scan(&count); err == nil {
			t.Fatalf("[%s] Expected gs_access_requests table to be dropped after 000004.up on populated DB", dialect)
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM gs_support_grants WHERE id = '"+grantID+"'").Scan(&count); err != nil || count != 1 {
			t.Fatalf("[%s] Expected existing gs_support_grants row to remain intact after 000004.up, got count=%d, err=%v", dialect, count, err)
		}
	})
}

// TestSQLMigrationFiles_FullLifecycle tests direct execution of physical .sql files (000001-000004) across all covered dialects.
func TestSQLMigrationFiles_FullLifecycle(t *testing.T) {
	ctx := context.Background()

	// 1. SQLite physical migration files (always runs in-memory)
	t.Run("sqlite", func(t *testing.T) {
		runDialectPhysicalMigrationsTest(t, ctx, "sqlite", func(t *testing.T, suffix string) *sql.DB {
			dbName := fmt.Sprintf("file:%s_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.New().String(), suffix)
			db, err := sql.Open("sqlite", dbName)
			if err != nil {
				t.Fatalf("Failed to open SQLite: %v", err)
			}
			return db
		})
	})

	// 2. Live dialects covered by migration tests (postgres, mysql, mariadb)
	liveDialects := []struct {
		name       string
		driver     string
		envVar     string
		defaultDSN string
	}{
		{
			name:       "postgres",
			driver:     "pgx",
			envVar:     "TEST_POSTGRES_URL",
			defaultDSN: "postgresql://grantsupport:secretpassword@127.0.0.1:5433/grantsupport?sslmode=disable",
		},
		{
			name:       "mysql",
			driver:     "mysql",
			envVar:     "TEST_MYSQL_URL",
			defaultDSN: "grantsupport:secretpassword@tcp(127.0.0.1:3306)/grantsupport?parseTime=true",
		},
		{
			name:       "mariadb",
			driver:     "mysql",
			envVar:     "TEST_MARIADB_URL",
			defaultDSN: "grantsupport:secretpassword@tcp(127.0.0.1:3307)/grantsupport?parseTime=true",
		},
	}

	for _, d := range liveDialects {
		t.Run(d.name, func(t *testing.T) {
			dsn := os.Getenv(d.envVar)
			if dsn == "" {
				dsn = d.defaultDSN
			}

			probeDB, err := sql.Open(d.driver, dsn)
			if err != nil {
				t.Skipf("Skipping %s physical migration test: %v", d.name, err)
				return
			}
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = probeDB.PingContext(pingCtx)
			cancel()
			_ = probeDB.Close()
			if err != nil {
				t.Skipf("Skipping %s physical migration test (database unreachable): %v", d.name, err)
				return
			}

			runDialectPhysicalMigrationsTest(t, ctx, d.name, func(t *testing.T, _ string) *sql.DB {
				db, openErr := sql.Open(d.driver, dsn)
				if openErr != nil {
					t.Fatalf("[%s] Failed to open DB: %v", d.name, openErr)
				}
				return db
			})
		})
	}
}
