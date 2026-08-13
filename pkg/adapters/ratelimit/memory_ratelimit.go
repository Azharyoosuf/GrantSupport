package ratelimit

import (
	"context"
	"sync"
	"time"
)

type rateBucket struct {
	tokens     int
	lastRefill time.Time
}

// MemoryRateLimiter implements ports.RateLimiterStore using in-memory token buckets.
type MemoryRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

// NewMemoryRateLimiter creates a new in-memory rate limiter.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{
		buckets: make(map[string]*rateBucket),
	}
}

// Allow evaluates if a request with key is permitted under limit per window.
func (r *MemoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	bucket, exists := r.buckets[key]
	if !exists || now.Sub(bucket.lastRefill) >= window {
		r.buckets[key] = &rateBucket{
			tokens:     limit - 1,
			lastRefill: now,
		}
		return true, nil
	}

	if bucket.tokens > 0 {
		bucket.tokens--
		return true, nil
	}

	return false, nil
}
