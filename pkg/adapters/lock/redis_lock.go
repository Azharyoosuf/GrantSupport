package lock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"grantsupport/pkg/ports"
)

// RedisLockStore implements ports.LockStore using Redis/Valkey SETNX and Lua scripts.
type RedisLockStore struct {
	client *redis.Client
}

// NewRedisLockStore initializes a new RedisLockStore with the given Redis/Valkey client.
func NewRedisLockStore(client *redis.Client) *RedisLockStore {
	return &RedisLockStore{client: client}
}

// Acquire attempts to acquire a distributed lock with a unique token and TTL.
func (s *RedisLockStore) Acquire(ctx context.Context, lockKey string, ttl time.Duration) (string, error) {
	if s.client == nil {
		return "", ports.ErrLockUnavailable
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate lock token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	ok, err := s.client.SetNX(ctx, lockKey, token, ttl).Result()
	if err != nil {
		return "", fmt.Errorf("failed to acquire lock: %w", err)
	}
	if !ok {
		return "", ports.ErrLockBusy
	}
	return token, nil
}

// Release safely releases the lock using a Lua script to verify token ownership.
func (s *RedisLockStore) Release(ctx context.Context, lockKey, token string) error {
	if s.client == nil {
		return nil
	}

	luaScript := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`
	return s.client.Eval(ctx, luaScript, []string{lockKey}, token).Err()
}

// WithLock wraps a function call within a distributed lock.
func (s *RedisLockStore) WithLock(ctx context.Context, lockKey string, ttl time.Duration, fn func(ctx context.Context) error) error {
	token, err := s.Acquire(ctx, lockKey, ttl)
	if err != nil {
		return err
	}
	defer func() {
		_ = s.Release(context.Background(), lockKey, token)
	}()

	return fn(ctx)
}
