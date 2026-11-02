package cache

import (
	"context"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// ValkeyClient wraps the Redis client pool with standard timeouts.
type ValkeyClient struct {
	Client *redis.Client
}

// NewValkeyClient parses the connection DSN and initializes connection pools.
func NewValkeyClient(dsn string) (*ValkeyClient, error) {
	normalizedDSN := dsn
	if strings.HasPrefix(normalizedDSN, "valkeys://") {
		normalizedDSN = "rediss://" + strings.TrimPrefix(normalizedDSN, "valkeys://")
	} else if strings.HasPrefix(normalizedDSN, "valkey://") {
		normalizedDSN = "redis://" + strings.TrimPrefix(normalizedDSN, "valkey://")
	}

	opts, err := redis.ParseURL(normalizedDSN)
	if err != nil {
		return nil, err
	}

	// Enforce strict latency timeouts matching our planning criteria
	opts.DialTimeout = 1 * time.Second
	opts.ReadTimeout = 500 * time.Millisecond
	opts.WriteTimeout = 500 * time.Millisecond
	opts.PoolSize = 10

	client := redis.NewClient(opts)

	// Verify connection immediately via ping
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, err
	}

	return &ValkeyClient{
		Client: client,
	}, nil
}

// Close gracefully closes the client connection pool.
func (vc *ValkeyClient) Close() error {
	if vc.Client != nil {
		return vc.Client.Close()
	}
	return nil
}
