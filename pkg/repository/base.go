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

// NewBaseRepository creates a new BaseRepository with a direct ent.Client.
func NewBaseRepository(masterClient *ent.Client) *BaseRepository {
	return &BaseRepository{
		MasterClient: masterClient,
	}
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
