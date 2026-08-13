package lock

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"grantsupport/pkg/ports"
)

// SQLLockStore implements ports.LockStore using the gs_locks database lease table.
type SQLLockStore struct {
	db      *sql.DB
	dialect string
	mu      sync.Mutex // fallback serialization for SQLite
}

// NewSQLLockStore constructs a new SQLLockStore instance.
func NewSQLLockStore(db *sql.DB, dialect string) *SQLLockStore {
	if dialect == "" {
		dialect = "postgres"
	}
	return &SQLLockStore{
		db:      db,
		dialect: dialect,
	}
}

// Acquire attempts to acquire a lease lock on lockKey for the given TTL.
func (s *SQLLockStore) Acquire(ctx context.Context, lockKey string, ttl time.Duration) (string, error) {
	if s.db == nil {
		return "", ports.ErrLockUnavailable
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate lock token: %w", err)
	}
	ownerToken := hex.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	switch s.dialect {
	case "sqlite", "sqlite3":
		s.mu.Lock()
		defer s.mu.Unlock()

		// Attempt takeover of expired lock
		res, err := s.db.ExecContext(ctx,
			"UPDATE gs_locks SET owner_token = ?, expires_at = ?, acquired_at = ? WHERE lock_key = ? AND expires_at < ?",
			ownerToken, expiresAt, now, lockKey, now)
		if err == nil {
			if rows, _ := res.RowsAffected(); rows > 0 {
				return ownerToken, nil
			}
		}

		// Attempt new insert
		_, err = s.db.ExecContext(ctx,
			"INSERT INTO gs_locks (lock_key, owner_token, expires_at, acquired_at) VALUES (?, ?, ?, ?)",
			lockKey, ownerToken, expiresAt, now)
		if err != nil {
			return "", ports.ErrLockBusy
		}
		return ownerToken, nil

	case "mysql", "mariadb":
		// Step 1: Attempt to take over expired lock
		res, err := s.db.ExecContext(ctx,
			"UPDATE gs_locks SET owner_token = ?, expires_at = ?, acquired_at = ? WHERE lock_key = ? AND expires_at < ?",
			ownerToken, expiresAt, now, lockKey, now)
		if err == nil {
			if rows, _ := res.RowsAffected(); rows > 0 {
				return ownerToken, nil
			}
		}

		// Step 2: Attempt new insertion with IGNORE
		res, err = s.db.ExecContext(ctx,
			"INSERT IGNORE INTO gs_locks (lock_key, owner_token, expires_at, acquired_at) VALUES (?, ?, ?, ?)",
			lockKey, ownerToken, expiresAt, now)
		if err != nil {
			return "", fmt.Errorf("failed to acquire lock: %w", err)
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			return ownerToken, nil
		}
		return "", ports.ErrLockBusy

	default: // "postgres", "pgx"
		query := `
			INSERT INTO gs_locks (lock_key, owner_token, expires_at, acquired_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (lock_key) DO UPDATE
			SET owner_token = EXCLUDED.owner_token,
			    expires_at = EXCLUDED.expires_at,
			    acquired_at = EXCLUDED.acquired_at
			WHERE gs_locks.expires_at < $4
		`
		res, err := s.db.ExecContext(ctx, query, lockKey, ownerToken, expiresAt, now)
		if err != nil {
			return "", fmt.Errorf("failed to execute lock query: %w", err)
		}

		rows, err := res.RowsAffected()
		if err != nil || rows == 0 {
			return "", ports.ErrLockBusy
		}
		return ownerToken, nil
	}
}

// Release safely releases the lock if and only if the owner token matches.
func (s *SQLLockStore) Release(ctx context.Context, lockKey, ownerToken string) error {
	if s.db == nil {
		return nil
	}

	var query string
	switch s.dialect {
	case "mysql", "mariadb", "sqlite", "sqlite3":
		query = "DELETE FROM gs_locks WHERE lock_key = ? AND owner_token = ?"
	default:
		query = "DELETE FROM gs_locks WHERE lock_key = $1 AND owner_token = $2"
	}

	_, err := s.db.ExecContext(ctx, query, lockKey, ownerToken)
	return err
}

// WithLock wraps a function call within an acquired lock, automatically releasing upon completion.
func (s *SQLLockStore) WithLock(ctx context.Context, lockKey string, ttl time.Duration, fn func(ctx context.Context) error) error {
	token, err := s.Acquire(ctx, lockKey, ttl)
	if err != nil {
		return err
	}
	defer func() {
		_ = s.Release(context.Background(), lockKey, token)
	}()

	return fn(ctx)
}
