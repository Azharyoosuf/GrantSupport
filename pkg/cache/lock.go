package cache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// LockService provides distributed locking capabilities with ownership verification.
type LockService struct {
	client *redis.Client
}

// NewLockService initializes a new LockService with the given Redis/Valkey client.
func NewLockService(client *redis.Client) *LockService {
	return &LockService{client: client}
}

// AcquireLock attempts to acquire a distributed lock with a unique token and TTL.
func (s *LockService) AcquireLock(ctx context.Context, lockKey string, ttl time.Duration) (string, error) {
	if s.client == nil {
		return "", errors.New("LOCK_UNAVAILABLE: Redis client not initialized")
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
		return "", fmt.Errorf("LOCK_BUSY: Resource is currently locked")
	}
	return token, nil
}

// ReleaseLock safely releases the lock using a Lua script to verify token ownership.
func (s *LockService) ReleaseLock(ctx context.Context, lockKey, token string) error {
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

// WithLock wraps a function call inside a distributed lock.
func (s *LockService) WithLock(ctx context.Context, lockKey string, ttl time.Duration, fn func(ctx context.Context) error) error {
	token, err := s.AcquireLock(ctx, lockKey, ttl)
	if err != nil {
		return err
	}
	defer func() {
		_ = s.ReleaseLock(context.Background(), lockKey, token)
	}()

	return fn(ctx)
}
