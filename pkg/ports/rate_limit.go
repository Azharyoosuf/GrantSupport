package ports

import (
	"context"
	"time"
)

// RateLimiterStore provides defense-in-depth request rate throttling.
type RateLimiterStore interface {
	// Allow checks whether an event for key is permitted under the specified limit and window.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}
