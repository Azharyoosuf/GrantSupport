package resilience

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type CircuitState string

const (
	StateClosed   CircuitState = "CLOSED"
	StateOpen     CircuitState = "OPEN"
	StateHalfOpen CircuitState = "HALF_OPEN"
)

// CircuitBreaker protects calls to unstable external services.
type CircuitBreaker struct {
	serviceName          string
	redisClient          *redis.Client
	localState           CircuitState
	localFailureCount    int
	localLastFailureTime int64
	FailureThreshold     int
	ResetTimeout         time.Duration
	mu                   sync.Mutex
}

// NewCircuitBreaker creates and configures a new CircuitBreaker.
func NewCircuitBreaker(serviceName string, redisClient *redis.Client) *CircuitBreaker {
	return &CircuitBreaker{
		serviceName:      serviceName,
		redisClient:      redisClient,
		localState:       StateClosed,
		FailureThreshold: 5,
		ResetTimeout:     30 * time.Second,
	}
}

// Execute wraps a service function call with circuit breaker protection.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() (any, error)) (any, error) {
	var currentState CircuitState = StateClosed
	var lastFailureTime int64 = 0
	var failureCount int = 0

	// 1. Fetch circuit state from Valkey (Redis)
	if cb.redisClient != nil {
		stateVal, err := cb.redisClient.Get(ctx, fmt.Sprintf("cb:%s:state", cb.serviceName)).Result()
		if err == nil {
			currentState = CircuitState(stateVal)
		}
		lastFailVal, err := cb.redisClient.Get(ctx, fmt.Sprintf("cb:%s:last_failure", cb.serviceName)).Result()
		if err == nil {
			if parsed, pErr := strconv.ParseInt(lastFailVal, 10, 64); pErr == nil {
				lastFailureTime = parsed
			}
		}
		failCountVal, err := cb.redisClient.Get(ctx, fmt.Sprintf("cb:%s:failures", cb.serviceName)).Result()
		if err == nil {
			if parsed, pErr := strconv.Atoi(failCountVal); pErr == nil {
				failureCount = parsed
			}
		}
	} else {
		// Use local state if Redis client is not configured
		cb.mu.Lock()
		currentState = cb.localState
		lastFailureTime = cb.localLastFailureTime
		failureCount = cb.localFailureCount
		cb.mu.Unlock()
	}

	// 2. Check if circuit is open and reset timeout has expired
	if currentState == StateOpen {
		nowMilli := time.Now().UnixMilli()
		if nowMilli-lastFailureTime > cb.ResetTimeout.Milliseconds() {
			slog.Info("Circuit breaker entering HALF_OPEN state", slog.String("service", cb.serviceName))
			currentState = StateHalfOpen
			cb.mu.Lock()
			cb.localState = StateHalfOpen
			cb.mu.Unlock()

			if cb.redisClient != nil {
				_ = cb.redisClient.Set(ctx, fmt.Sprintf("cb:%s:state", cb.serviceName), string(StateHalfOpen), 0).Err()
			}
		} else {
			return nil, fmt.Errorf("CIRCUIT_OPEN: Service %s is temporarily unavailable", cb.serviceName)
		}
	}

	// 3. Execute the payload callback
	result, err := fn()
	if err != nil {
		cb.onFailure(ctx, failureCount)
		return nil, err
	}

	cb.onSuccess(ctx)
	return result, nil
}

func (cb *CircuitBreaker) onSuccess(ctx context.Context) {
	cb.mu.Lock()
	cb.localState = StateClosed
	cb.localFailureCount = 0
	cb.mu.Unlock()

	if cb.redisClient != nil {
		_ = cb.redisClient.Set(ctx, fmt.Sprintf("cb:%s:state", cb.serviceName), string(StateClosed), 0).Err()
		_ = cb.redisClient.Set(ctx, fmt.Sprintf("cb:%s:failures", cb.serviceName), "0", 0).Err()
	}
}

func (cb *CircuitBreaker) onFailure(ctx context.Context, currentFailCount int) {
	newFailCount := currentFailCount + 1
	newLastFailureTime := time.Now().UnixMilli()
	var newState CircuitState = StateClosed

	if newFailCount >= cb.FailureThreshold {
		slog.Error("Circuit breaker tripped! Entering OPEN state", slog.String("service", cb.serviceName))
		newState = StateOpen
	}

	cb.mu.Lock()
	cb.localFailureCount = newFailCount
	cb.localLastFailureTime = newLastFailureTime
	if newState == StateOpen {
		cb.localState = StateOpen
	}
	cb.mu.Unlock()

	if cb.redisClient != nil {
		_ = cb.redisClient.Set(ctx, fmt.Sprintf("cb:%s:failures", cb.serviceName), strconv.Itoa(newFailCount), 0).Err()
		_ = cb.redisClient.Set(ctx, fmt.Sprintf("cb:%s:last_failure", cb.serviceName), strconv.FormatInt(newLastFailureTime, 10), 0).Err()
		if newState == StateOpen {
			_ = cb.redisClient.Set(ctx, fmt.Sprintf("cb:%s:state", cb.serviceName), string(StateOpen), 0).Err()
		}
	}
}
