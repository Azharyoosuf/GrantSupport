package revocation

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// RedisRevocationStore implements ports.RevocationStore using Redis/Valkey keys.
type RedisRevocationStore struct {
	client *redis.Client
}

// NewRedisRevocationStore creates a new RedisRevocationStore instance.
func NewRedisRevocationStore(client *redis.Client) *RedisRevocationStore {
	return &RedisRevocationStore{client: client}
}

// IsTokenRevoked checks whether the cached token version in Redis is greater than tokenVersion.
func (s *RedisRevocationStore) IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error) {
	if s.client == nil {
		return false, fmt.Errorf("revocation store unavailable: redis client not configured")
	}

	cacheKey := fmt.Sprintf("cache:%s:user:security:%s", institutionID, userID)
	cachedVersion, err := s.client.Get(ctx, cacheKey).Int()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return cachedVersion > tokenVersion, nil
}

// RevokeUserSessions sets the minimum valid token version in Redis.
func (s *RedisRevocationStore) RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error {
	if s.client == nil {
		return fmt.Errorf("redis client not configured")
	}

	cacheKey := fmt.Sprintf("cache:%s:user:security:%s", institutionID, userID)
	return s.client.Set(ctx, cacheKey, newVersion, 0).Err()
}
