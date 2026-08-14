package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"grantsupport/ent"
)

// BaseRepository encapsulates the Ent database client and underlying sql.DB.
type BaseRepository struct {
	MasterClient *ent.Client
	SQLDB        *sql.DB
	Dialect      string
}

// NewBaseRepository creates a new BaseRepository with a direct ent.Client, automatically detecting any underlying *sql.DB and SQL dialect.
func NewBaseRepository(masterClient *ent.Client) *BaseRepository {
	repo := &BaseRepository{
		MasterClient: masterClient,
	}
	if masterClient != nil {
		drv := masterClient.Driver()
		if dbGetter, ok := drv.(interface{ DB() *sql.DB }); ok {
			repo.SQLDB = dbGetter.DB()
		}
		if dialectGetter, ok := drv.(interface{ Dialect() string }); ok {
			repo.Dialect = dialectGetter.Dialect()
		}
	}
	return repo
}

// NewBaseRepositoryWithDB creates a new BaseRepository by wrapping an existing *sql.DB connection pool.
func NewBaseRepositoryWithDB(db *sql.DB, dialectName string) *BaseRepository {
	var entDialect string
	switch dialectName {
	case "mysql", "mariadb":
		entDialect = dialect.MySQL
	case "sqlite", "sqlite3":
		entDialect = dialect.SQLite
	default:
		entDialect = dialect.Postgres
	}

	drv := entsql.OpenDB(entDialect, db)
	client := ent.NewClient(ent.Driver(drv))

	return &BaseRepository{
		MasterClient: client,
		SQLDB:        db,
		Dialect:      dialectName,
	}
}

// GetClient returns the Ent client for database operations.
func (r *BaseRepository) GetClient(ctx context.Context) (*ent.Client, error) {
	if r.MasterClient == nil {
		return nil, fmt.Errorf("master database client not initialized")
	}
	return r.MasterClient, nil
}

// Transaction executes a transactional callback inside an Ent transaction (ent.Tx).
// Enforces a 10-second transaction timeout limit matching local and production guardrails.
func (r *BaseRepository) Transaction(ctx context.Context, fn func(tx *ent.Tx) error) error {
	client, err := r.GetClient(ctx)
	if err != nil {
		return err
	}

	txCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	tx, err := client.Tx(txCtx)
	if err != nil {
		return fmt.Errorf("failed to start database transaction: %w", err)
	}

	// Defer recovery to rollback transaction on panic
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // Re-panic after safety rollback
		}
	}()

	err = fn(tx)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("transaction failed: %v (rollback error: %v)", err, rollbackErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit database transaction: %w", err)
	}
	return nil
}

// CreateCapabilityTables creates the SQL capability tables (gs_locks, gs_replays, gs_revocations) for the specified database dialect.
func CreateCapabilityTables(ctx context.Context, db *sql.DB, dialect string) error {
	if db == nil {
		return nil
	}

	var ddl string
	switch dialect {
	case "sqlite", "sqlite3":
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (
			lock_key TEXT PRIMARY KEY,
			owner_token TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			acquired_at DATETIME NOT NULL
		);
		CREATE TABLE IF NOT EXISTS gs_replays (
			nonce_key TEXT PRIMARY KEY,
			expires_at DATETIME NOT NULL
		);
		CREATE TABLE IF NOT EXISTS gs_revocations (
			institution_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			token_version INTEGER NOT NULL DEFAULT 1,
			revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (institution_id, user_id)
		);`
	case "mysql", "mariadb":
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (
			lock_key VARCHAR(255) PRIMARY KEY,
			owner_token VARCHAR(64) NOT NULL,
			expires_at DATETIME(6) NOT NULL,
			acquired_at DATETIME(6) NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		CREATE TABLE IF NOT EXISTS gs_replays (
			nonce_key VARCHAR(255) PRIMARY KEY,
			expires_at DATETIME(6) NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		CREATE TABLE IF NOT EXISTS gs_revocations (
			institution_id VARCHAR(36) NOT NULL,
			user_id VARCHAR(36) NOT NULL,
			token_version INT NOT NULL DEFAULT 1,
			revoked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			PRIMARY KEY (institution_id, user_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`
	default: // postgres, pgx
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (
			lock_key VARCHAR(255) PRIMARY KEY,
			owner_token VARCHAR(64) NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			acquired_at TIMESTAMPTZ NOT NULL
		);
		CREATE TABLE IF NOT EXISTS gs_replays (
			nonce_key VARCHAR(255) PRIMARY KEY,
			expires_at TIMESTAMPTZ NOT NULL
		);
		CREATE TABLE IF NOT EXISTS gs_revocations (
			institution_id UUID NOT NULL,
			user_id UUID NOT NULL,
			token_version INTEGER NOT NULL DEFAULT 1,
			revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (institution_id, user_id)
		);`
	}

	_, err := db.ExecContext(ctx, ddl)
	return err
}
