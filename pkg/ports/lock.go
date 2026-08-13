package ports

import (
	"context"
	"errors"
	"time"
)

var (
	ErrLockBusy        = errors.New("LOCK_BUSY: Resource is currently locked by another process")
	ErrLockUnavailable = errors.New("LOCK_UNAVAILABLE: Distributed lock service is unavailable")
)

// LockStore provides distributed concurrency locking with ownership verification.
type LockStore interface {
	// Acquire attempts to acquire a lock with the specified key and TTL.
	// Returns a unique owner token if successful, or ErrLockBusy if already held.
	Acquire(ctx context.Context, lockKey string, ttl time.Duration) (string, error)

	// Release safely releases the lock if and only if the owner token matches.
	Release(ctx context.Context, lockKey, ownerToken string) error

	// WithLock wraps a function call within an acquired lock, automatically releasing upon completion.
	WithLock(ctx context.Context, lockKey string, ttl time.Duration, fn func(ctx context.Context) error) error
}
