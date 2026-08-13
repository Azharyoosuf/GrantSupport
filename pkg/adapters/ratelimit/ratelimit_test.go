package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"grantsupport/pkg/adapters/ratelimit"
)

func TestMemoryRateLimiter(t *testing.T) {
	limiter := ratelimit.NewMemoryRateLimiter()
	ctx := context.Background()
	key := "ip:127.0.0.1:login"
	limit := 3
	window := 200 * time.Millisecond

	// First 3 requests allowed
	for i := 1; i <= limit; i++ {
		allow, err := limiter.Allow(ctx, key, limit, window)
		if err != nil || !allow {
			t.Fatalf("Expected request %d to be allowed, got allow=%v, err=%v", i, allow, err)
		}
	}

	// 4th request exceeds limit
	allow, err := limiter.Allow(ctx, key, limit, window)
	if err != nil || allow {
		t.Fatalf("Expected 4th request to be throttled, got allow=%v, err=%v", allow, err)
	}

	// Wait for window to reset
	time.Sleep(250 * time.Millisecond)

	// Should be allowed again after window refill
	allow, err = limiter.Allow(ctx, key, limit, window)
	if err != nil || !allow {
		t.Fatalf("Expected request after window reset to be allowed, got allow=%v, err=%v", allow, err)
	}
}
