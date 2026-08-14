package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements ports.RateLimiterStore using Redis INCR and EXPIRE.
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

	rateKey := fmt.Sprintf("ratelimit:%s", key)
	count, err := r.client.Incr(ctx, rateKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to evaluate redis rate limit: %w", err)
	}

	if count == 1 {
		_ = r.client.Expire(ctx, rateKey, window).Err()
	}

	return count <= int64(limit), nil
}
