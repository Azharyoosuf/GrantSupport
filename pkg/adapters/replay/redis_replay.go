package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"grantsupport/pkg/ports"
)

// RedisReplayStore implements ports.ReplayStore using Redis/Valkey SETNX with TTL.
type RedisReplayStore struct {
	client *redis.Client
}

// NewRedisReplayStore creates a new RedisReplayStore instance.
func NewRedisReplayStore(client *redis.Client) *RedisReplayStore {
	return &RedisReplayStore{client: client}
}

// CheckAndSet sets the nonce in Redis if it does not already exist.
func (s *RedisReplayStore) CheckAndSet(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	if s.client == nil {
		return false, fmt.Errorf("redis client not configured")
	}

	nonceKey := fmt.Sprintf("nonce:%s:%s", keyID, nonce)
	ok, err := s.client.SetNX(ctx, nonceKey, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check nonce in redis: %w", err)
	}
	if !ok {
		return false, ports.ErrReplayDetected
	}
	return true, nil
}
