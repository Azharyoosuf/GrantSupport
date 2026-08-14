package grantsupport_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/security"
)

// BenchmarkJWTVerification measures the throughput of RS256 JWT public-key verification.
func BenchmarkJWTVerification(b *testing.B) {
	_ = security.SetupTestRSAKeys()

	token, err := security.GenerateJWT("agent-123", "inst-456", "SUPPORT_AGENT", 1*time.Hour)
	if err != nil {
		b.Fatalf("GenerateJWT failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := security.VerifyJWT(token)
		if err != nil {
			b.Fatalf("VerifyJWT failed: %v", err)
		}
	}
}

// BenchmarkJWTSigning measures the speed of RS256 private-key JWT generation.
func BenchmarkJWTSigning(b *testing.B) {
	_ = security.SetupTestRSAKeys()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := security.GenerateJWT("agent-123", "inst-456", "SUPPORT_AGENT", 1*time.Hour)
		if err != nil {
			b.Fatalf("GenerateJWT failed: %v", err)
		}
	}
}

// BenchmarkGrantCreation measures the end-to-end grant creation speed with crypto random token generation & DB write.
func BenchmarkGrantCreation(b *testing.B) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:bench_grant_create?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		b.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		b.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
		if err != nil {
			b.Fatalf("CreateSupportGrant failed: %v", err)
		}
	}
}

// BenchmarkSupportLogin measures end-to-end token redemption, atomic CAS consumption, and JWT issuance.
func BenchmarkSupportLogin(b *testing.B) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:bench_support_login?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		b.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		b.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Pre-generate grants for the benchmark iterations
	tokens := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		tokens[i], err = engine.CreateSupportGrant(ctx, instID, adminID, 60, "FULL_ACCESS", nil)
		if err != nil {
			b.Fatalf("Pre-creating grant failed: %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, err := engine.SupportLogin(ctx, tokens[i], agentID)
		if err != nil {
			b.Fatalf("SupportLogin failed: %v", err)
		}
	}
}

// BenchmarkRevocationCheck measures the speed of checking token revocation in the SQL store.
func BenchmarkRevocationCheck(b *testing.B) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:bench_revocation_check?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		b.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	_, _ = db.ExecContext(ctx, `
		CREATE TABLE gs_revocations (
			institution_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			token_version INTEGER NOT NULL DEFAULT 1,
			revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (institution_id, user_id)
		);
	`)

	store := revocation.NewSQLRevocationStore(db, "sqlite")
	instID := uuid.New().String()
	userID := uuid.New().String()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := store.IsTokenRevoked(ctx, instID, userID, 1)
		if err != nil {
			b.Fatalf("IsTokenRevoked failed: %v", err)
		}
	}
}
