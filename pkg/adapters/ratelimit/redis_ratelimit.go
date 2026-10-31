package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// incrWithExpireScript atomically increments a rate-limit counter and ensures it always has a positive TTL,
// repairing any pre-existing counter that lacked an expiration.
var incrWithExpireScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 or redis.call("PTTL", KEYS[1]) < 0 then
	redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return count
`)

// RedisRateLimiter implements ports.RateLimiterStore using an atomic Redis Lua script (INCR + PEXPIRE).
type RedisRateLimiter struct {
	client *redis.Client
}

// NewRedisRateLimiter creates a new RedisRateLimiter instance.
func NewRedisRateLimiter(client *redis.Client) *RedisRateLimiter {
	return &RedisRateLimiter{client: client}
}

// Allow checks if the counter for key is within the limit for the given duration window.
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil
	}
	if r.client == nil {
		return false, fmt.Errorf("rate limiter unavailable: redis client not configured")
	}

	windowMs := window.Milliseconds()
	if windowMs <= 0 {
		windowMs = 1000
	}

	rateKey := fmt.Sprintf("ratelimit:%s", key)
	count, err := incrWithExpireScript.Run(ctx, r.client, []string{rateKey}, windowMs).Int64()
	if err != nil {
		return false, fmt.Errorf("failed to evaluate redis rate limit: %w", err)
	}

	return count <= int64(limit), nil
}
