package ports

import (
	"context"
	"errors"
)

var (
	ErrTokenRevoked = errors.New("TOKEN_REVOKED: Session or token version has been revoked")
)

// RevocationStore manages token and session invalidation state across nodes.
type RevocationStore interface {
	// IsTokenRevoked returns true if the token version for the user/institution is older than the current valid version.
	IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error)

	// RevokeUserSessions increments or sets the minimum valid token version for a user, revoking earlier sessions.
	RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error
}
