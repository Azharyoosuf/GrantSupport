package replay

import (
	"context"
	"fmt"
	"sync"
	"time"

	"grantsupport/pkg/ports"
)

type nonceEntry struct {
	expiresAt time.Time
}

// MemoryReplayStore implements ports.ReplayStore in-memory for single-instance deployments.
type MemoryReplayStore struct {
	mu     sync.RWMutex
	nonces map[string]nonceEntry
	stopCh chan struct{}
}

// NewMemoryReplayStore creates a new in-memory replay cache with periodic background eviction.
func NewMemoryReplayStore(cleanupInterval time.Duration) *MemoryReplayStore {
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Minute
	}

	store := &MemoryReplayStore{
		nonces: make(map[string]nonceEntry),
		stopCh: make(chan struct{}),
	}

	go store.startCleanup(cleanupInterval)
	return store
}

// CheckAndSet returns true if the nonce was not previously registered within its TTL.
func (s *MemoryReplayStore) CheckAndSet(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	key := fmt.Sprintf("%s:%s", keyID, nonce)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.nonces[key]; exists {
		if entry.expiresAt.After(now) {
			return false, ports.ErrReplayDetected
		}
	}

	s.nonces[key] = nonceEntry{
		expiresAt: now.Add(ttl),
	}
	return true, nil
}

func (s *MemoryReplayStore) startCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.evictExpired()
		}
	}
}

func (s *MemoryReplayStore) evictExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, entry := range s.nonces {
		if entry.expiresAt.Before(now) {
			delete(s.nonces, key)
		}
	}
}

// Close stops the background eviction goroutine.
func (s *MemoryReplayStore) Close() {
	close(s.stopCh)
}
