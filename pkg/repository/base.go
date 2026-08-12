package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"grantsupport/ent"

	pkgctx "grantsupport/pkg/context"
	pkgdb "grantsupport/pkg/database"
)

// BaseRepository encapsulates shared connection managers and database wrappers.
type BaseRepository struct {
	MasterClient  *ent.Client
	TenantConnMgr *pkgdb.TenantConnectionManager
	PgxPool       *pgxpool.Pool
	Valkey        *redis.Client
}

// NewBaseRepository creates a new BaseRepository instance.
func NewBaseRepository(masterClient *ent.Client, tenantConnMgr *pkgdb.TenantConnectionManager, pgxPool *pgxpool.Pool, valkey *redis.Client) *BaseRepository {
	return &BaseRepository{
		MasterClient:  masterClient,
		TenantConnMgr: tenantConnMgr,
		PgxPool:       pgxPool,
		Valkey:        valkey,
	}
}

// GetClient resolves the correct Ent client for the active tenant context.
func (r *BaseRepository) GetClient(ctx context.Context) (*ent.Client, error) {
	tenant, ok := pkgctx.GetTenant(ctx)
	if !ok || tenant == nil || tenant.InstitutionID == uuid.Nil || tenant.Role == "PLATFORM_OWNER" {
		// Fallback to MasterClient if context has no tenant or is platform owner
		return r.MasterClient, nil
	}
	return r.TenantConnMgr.GetClient(ctx, tenant.InstitutionID)
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

	// 🛡️ ROW LEVEL SECURITY: Inject active tenant ID into the transaction context.
	// Set the current institution_id parameter in PostgreSQL local session variables.
	tenant, ok := pkgctx.GetTenant(ctx)
	if ok && tenant != nil {
		if tenant.Role == "PLATFORM_OWNER" {
			err = tx.ExecRaw(txCtx, "SET LOCAL app.bypass_rls = 'true'")
			if err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("failed to set RLS bypass context: %w", err)
			}
		} else if tenant.InstitutionID != uuid.Nil {
			instIDStr := tenant.InstitutionID.String()
			if _, parseErr := uuid.Parse(instIDStr); parseErr != nil {
				_ = tx.Rollback()
				return fmt.Errorf("invalid tenant institution ID format for RLS context: %w", parseErr)
			}
			err = tx.ExecRaw(txCtx, "SET LOCAL app.current_institution_id = $1", instIDStr)
			if err != nil {
				// Fallback for drivers that do not support parameter binding on SET LOCAL statements
				err = tx.ExecRaw(txCtx, fmt.Sprintf("SET LOCAL app.current_institution_id = '%s'", instIDStr))
				if err != nil {
					_ = tx.Rollback()
					return fmt.Errorf("failed to set RLS tenant context: %w", err)
				}
			}
		}
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
