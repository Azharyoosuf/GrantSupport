package ports

import (
	"context"
	"errors"
	"time"
)

var (
	ErrReplayDetected = errors.New("REPLAY_ATTACK_DETECTED: Duplicate request nonce detected")
)

// ReplayStore provides cryptographic nonce tracking to prevent request replay attacks.
type ReplayStore interface {
	// CheckAndSet returns true if the nonce is new and was successfully registered.
	// Returns false or ErrReplayDetected if the nonce has already been seen within its TTL window.
	CheckAndSet(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error)
}
