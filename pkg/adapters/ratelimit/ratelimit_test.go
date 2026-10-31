package ratelimit_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"grantsupport/pkg/adapters/ratelimit"
	"grantsupport/pkg/cache"
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

func TestRedisRateLimiter_NilClientFailsClosed(t *testing.T) {
	limiter := ratelimit.NewRedisRateLimiter(nil)
	ctx := context.Background()

	allow, err := limiter.Allow(ctx, "ip:127.0.0.1:login", 5, 1*time.Minute)
	if err == nil {
		t.Fatal("Expected error from nil Redis client in RedisRateLimiter")
	}
	if allow {
		t.Fatal("Expected allow=false on Redis error (fail-closed)")
	}
}

func TestRedisRateLimiter_AtomicTTLAndRepairAgainstValkey(t *testing.T) {
	valkeyURL := os.Getenv("VALKEY_CACHE_URL")
	if valkeyURL == "" {
		valkeyURL = "valkey://127.0.0.1:6379/0"
	}
	vc, err := cache.NewValkeyClient(valkeyURL)
	if err != nil {
		t.Fatalf("Failed to connect to live Valkey (%s): %v", valkeyURL, err)
	}
	defer vc.Close()
	rdb := vc.Client

	ctx := context.Background()
	limiter := ratelimit.NewRedisRateLimiter(rdb)

	// 1. Fresh key: TTL is always positive after Allow, and limit is enforced
	freshKey := "test:fresh:" + uuid.NewString()
	rawFreshKey := fmt.Sprintf("ratelimit:%s", freshKey)
	defer rdb.Del(ctx, rawFreshKey)

	window := 10 * time.Second
	for i := 1; i <= 3; i++ {
		allowed, err := limiter.Allow(ctx, freshKey, 2, window)
		if err != nil {
			t.Fatalf("Allow call %d failed: %v", i, err)
		}
		expectedAllow := i <= 2
		if allowed != expectedAllow {
			t.Fatalf("Allow call %d: expected %v, got %v", i, expectedAllow, allowed)
		}
		pttl, err := rdb.PTTL(ctx, rawFreshKey).Result()
		if err != nil {
			t.Fatalf("PTTL failed: %v", err)
		}
		if pttl <= 0 {
			t.Fatalf("Allow call %d: expected positive TTL on %s, got %v", i, rawFreshKey, pttl)
		}
	}

	// 2. Pre-existing key seeded without a TTL (PTTL == -1) is repaired with a positive TTL on Allow
	orphanKey := "test:orphan:" + uuid.NewString()
	rawOrphanKey := fmt.Sprintf("ratelimit:%s", orphanKey)
	defer rdb.Del(ctx, rawOrphanKey)

	if err := rdb.Set(ctx, rawOrphanKey, "1", 0).Err(); err != nil {
		t.Fatalf("failed to seed orphan key without TTL: %v", err)
	}
	if pttl := rdb.PTTL(ctx, rawOrphanKey).Val(); pttl >= 0 {
		t.Fatalf("expected seeded key to have no TTL (<0), got %v", pttl)
	}

	allowed, err := limiter.Allow(ctx, orphanKey, 5, window)
	if err != nil || !allowed {
		t.Fatalf("expected Allow on seeded key (count=2 <= 5) to succeed, got allowed=%v err=%v", allowed, err)
	}

	repairedTTL, err := rdb.PTTL(ctx, rawOrphanKey).Result()
	if err != nil {
		t.Fatalf("PTTL failed: %v", err)
	}
	if repairedTTL <= 0 {
		t.Fatalf("expected key seeded without TTL to be repaired with a positive TTL after Allow, got %v", repairedTTL)
	}
}
