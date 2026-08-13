package lock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"grantsupport/pkg/ports"
)

type lockEntry struct {
	ownerToken string
	expiresAt  time.Time
}

// MemoryLockStore implements ports.LockStore using an in-memory map and mutex for single-instance deployments.
type MemoryLockStore struct {
	mu    sync.Mutex
	locks map[string]lockEntry
}

// NewMemoryLockStore constructs a new MemoryLockStore instance.
func NewMemoryLockStore() *MemoryLockStore {
	return &MemoryLockStore{
		locks: make(map[string]lockEntry),
	}
}

// Acquire attempts to acquire a lock for lockKey with the given TTL.
func (s *MemoryLockStore) Acquire(ctx context.Context, lockKey string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if entry, exists := s.locks[lockKey]; exists {
		if entry.expiresAt.After(now) {
			return "", ports.ErrLockBusy
		}
	}

	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	ownerToken := hex.EncodeToString(tokenBytes)

	s.locks[lockKey] = lockEntry{
		ownerToken: ownerToken,
		expiresAt:  now.Add(ttl),
	}
	return ownerToken, nil
}

// Release safely releases the lock if and only if the ownerToken matches.
func (s *MemoryLockStore) Release(ctx context.Context, lockKey, ownerToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.locks[lockKey]; exists {
		if entry.ownerToken == ownerToken {
			delete(s.locks, lockKey)
		}
	}
	return nil
}

// WithLock wraps a function call within an acquired lock.
func (s *MemoryLockStore) WithLock(ctx context.Context, lockKey string, ttl time.Duration, fn func(ctx context.Context) error) error {
	token, err := s.Acquire(ctx, lockKey, ttl)
	if err != nil {
		return err
	}
	defer func() {
		_ = s.Release(context.Background(), lockKey, token)
	}()

	return fn(ctx)
}
