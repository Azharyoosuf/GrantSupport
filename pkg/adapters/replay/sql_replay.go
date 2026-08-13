package replay

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"grantsupport/pkg/ports"
)

// SQLReplayStore implements ports.ReplayStore using the gs_replays database table.
type SQLReplayStore struct {
	db      *sql.DB
	dialect string
}

// NewSQLReplayStore creates a new SQL-backed replay store.
func NewSQLReplayStore(db *sql.DB, dialect string) *SQLReplayStore {
	if dialect == "" {
		dialect = "postgres"
	}
	return &SQLReplayStore{
		db:      db,
		dialect: dialect,
	}
}

// CheckAndSet registers a nonce if it does not already exist.
func (s *SQLReplayStore) CheckAndSet(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	if s.db == nil {
		return false, fmt.Errorf("database connection is nil")
	}

	nonceKey := fmt.Sprintf("%s:%s", keyID, nonce)
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	switch s.dialect {
	case "sqlite", "sqlite3":
		// Clean up expired entry if it exists
		_, _ = s.db.ExecContext(ctx, "DELETE FROM gs_replays WHERE nonce_key = ? AND expires_at < ?", nonceKey, now)

		_, err := s.db.ExecContext(ctx, "INSERT INTO gs_replays (nonce_key, expires_at) VALUES (?, ?)", nonceKey, expiresAt)
		if err != nil {
			return false, ports.ErrReplayDetected
		}
		return true, nil

	case "mysql", "mariadb":
		// Takeover or clean up expired entry
		_, _ = s.db.ExecContext(ctx, "DELETE FROM gs_replays WHERE nonce_key = ? AND expires_at < ?", nonceKey, now)

		res, err := s.db.ExecContext(ctx, "INSERT IGNORE INTO gs_replays (nonce_key, expires_at) VALUES (?, ?)", nonceKey, expiresAt)
		if err != nil {
			return false, err
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			return false, ports.ErrReplayDetected
		}
		return true, nil

	default: // "postgres", "pgx"
		query := `
			INSERT INTO gs_replays (nonce_key, expires_at)
			VALUES ($1, $2)
			ON CONFLICT (nonce_key) DO UPDATE
			SET expires_at = EXCLUDED.expires_at
			WHERE gs_replays.expires_at < $3
		`
		res, err := s.db.ExecContext(ctx, query, nonceKey, expiresAt, now)
		if err != nil {
			return false, err
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			return false, ports.ErrReplayDetected
		}
		return true, nil
	}
}
