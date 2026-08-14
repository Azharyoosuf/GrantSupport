package revocation

import (
	"context"
	"database/sql"
	"fmt"
)

// SQLRevocationStore implements ports.RevocationStore using the gs_revocations table.
type SQLRevocationStore struct {
	db      *sql.DB
	dialect string
}

// NewSQLRevocationStore creates a new SQL-backed revocation store.
func NewSQLRevocationStore(db *sql.DB, dialect string) *SQLRevocationStore {
	if dialect == "" {
		dialect = "postgres"
	}
	return &SQLRevocationStore{
		db:      db,
		dialect: dialect,
	}
}

// IsTokenRevoked returns true if the user's current minimum valid token version is greater than tokenVersion.
func (s *SQLRevocationStore) IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error) {
	if s.db == nil {
		return false, fmt.Errorf("revocation store not configured: no database connection")
	}

	var currentVersion int
	var query string
	switch s.dialect {
	case "mysql", "mariadb", "sqlite", "sqlite3":
		query = "SELECT token_version FROM gs_revocations WHERE institution_id = ? AND user_id = ?"
	default:
		query = "SELECT token_version FROM gs_revocations WHERE institution_id = $1 AND user_id = $2"
	}

	err := s.db.QueryRowContext(ctx, query, institutionID, userID).Scan(&currentVersion)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return currentVersion > tokenVersion, nil
}

// GetUserTokenVersion returns the user's current token version from the database (defaults to 1 if no record).
func (s *SQLRevocationStore) GetUserTokenVersion(ctx context.Context, institutionID, userID string) (int, error) {
	if s.db == nil {
		return 0, fmt.Errorf("revocation store not configured: no database connection")
	}

	var currentVersion int
	var query string
	switch s.dialect {
	case "mysql", "mariadb", "sqlite", "sqlite3":
		query = "SELECT token_version FROM gs_revocations WHERE institution_id = ? AND user_id = ?"
	default:
		query = "SELECT token_version FROM gs_revocations WHERE institution_id = $1 AND user_id = $2"
	}

	err := s.db.QueryRowContext(ctx, query, institutionID, userID).Scan(&currentVersion)
	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	if currentVersion < 1 {
		return 1, nil
	}

	return currentVersion, nil
}

// RevokeUserSessions updates the minimum valid token version for a user.
func (s *SQLRevocationStore) RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error {
	if s.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	switch s.dialect {
	case "sqlite", "sqlite3":
		query := `
			INSERT INTO gs_revocations (institution_id, user_id, token_version, revoked_at)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (institution_id, user_id) DO UPDATE
			SET token_version = ?, revoked_at = CURRENT_TIMESTAMP
		`
		_, err := s.db.ExecContext(ctx, query, institutionID, userID, newVersion, newVersion)
		return err

	case "mysql", "mariadb":
		query := `
			INSERT INTO gs_revocations (institution_id, user_id, token_version, revoked_at)
			VALUES (?, ?, ?, NOW(6))
			ON DUPLICATE KEY UPDATE
			token_version = VALUES(token_version), revoked_at = VALUES(revoked_at)
		`
		_, err := s.db.ExecContext(ctx, query, institutionID, userID, newVersion)
		return err

	default: // "postgres", "pgx"
		query := `
			INSERT INTO gs_revocations (institution_id, user_id, token_version, revoked_at)
			VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
			ON CONFLICT (institution_id, user_id) DO UPDATE
			SET token_version = EXCLUDED.token_version, revoked_at = EXCLUDED.revoked_at
		`
		_, err := s.db.ExecContext(ctx, query, institutionID, userID, newVersion)
		return err
	}
}
