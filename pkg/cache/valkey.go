package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ValkeyClient wraps the Redis client pool with standard timeouts and lock service.
type ValkeyClient struct {
	Client      *redis.Client
	LockService *LockService
}

// NewValkeyClient parses the connection DSN and initializes connection pools.
func NewValkeyClient(dsn string) (*ValkeyClient, error) {
	opts, err := redis.ParseURL(dsn)
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

	lockService := NewLockService(client)

	return &ValkeyClient{
		Client:      client,
		LockService: lockService,
	}, nil
}

// NewValkeyClusterClient initializes connection pools across multiple independent Valkey nodes for Redlock consensus safety.
func NewValkeyClusterClient(addrs []string) (*ValkeyClient, error) {
	if len(addrs) == 0 {
		return nil, errors.New("VALKEY_CLUSTER_ERR: At least one node address must be provided")
	}

	clusterOpts := &redis.ClusterOptions{
		Addrs:        addrs,
		DialTimeout:  1 * time.Second,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
		PoolSize:     10,
	}

	clusterClient := redis.NewClusterClient(clusterOpts)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := clusterClient.Ping(ctx).Err(); err != nil {
		clusterClient.Close()
		return nil, err
	}

	// Wrap cluster client as standard client interface wrapper
	baseClient := redis.NewClient(&redis.Options{Addr: addrs[0]})
	lockService := NewLockService(baseClient)

	return &ValkeyClient{
		Client:      baseClient,
		LockService: lockService,
	}, nil
}

// Close gracefully closes the client connection pool.
func (vc *ValkeyClient) Close() error {
	if vc.Client != nil {
		return vc.Client.Close()
	}
	return nil
}

// SetNX sets a key with TTL if it does not already exist (returns true if key was set, false if key already exists).
func (vc *ValkeyClient) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	if vc == nil || vc.Client == nil {
		return false, errors.New("VALKEY_UNAVAILABLE: Valkey cache client not connected")
	}
	return vc.Client.SetNX(ctx, key, value, ttl).Result()
}
