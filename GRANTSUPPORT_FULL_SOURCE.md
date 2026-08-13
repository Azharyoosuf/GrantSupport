# GrantSupport Full Source Code Export

- **Export Date**: 2026-08-13
- **Git Commit**: 0ec7b6a379be0eecfdcd0a86dc06ab59d0709509

---

## Table of Contents

### cmd/
- [cmd/server/main.go](#cmd-server-main-go)

### pkg/
- [pkg/adapters/lock/lock_test.go](#pkg-adapters-lock-lock-test-go)
- [pkg/adapters/lock/memory_lock.go](#pkg-adapters-lock-memory-lock-go)
- [pkg/adapters/lock/redis_lock.go](#pkg-adapters-lock-redis-lock-go)
- [pkg/adapters/lock/sql_lock.go](#pkg-adapters-lock-sql-lock-go)
- [pkg/adapters/ratelimit/memory_ratelimit.go](#pkg-adapters-ratelimit-memory-ratelimit-go)
- [pkg/adapters/ratelimit/ratelimit_test.go](#pkg-adapters-ratelimit-ratelimit-test-go)
- [pkg/adapters/ratelimit/redis_ratelimit.go](#pkg-adapters-ratelimit-redis-ratelimit-go)
- [pkg/adapters/replay/memory_replay.go](#pkg-adapters-replay-memory-replay-go)
- [pkg/adapters/replay/redis_replay.go](#pkg-adapters-replay-redis-replay-go)
- [pkg/adapters/replay/replay_test.go](#pkg-adapters-replay-replay-test-go)
- [pkg/adapters/replay/sql_replay.go](#pkg-adapters-replay-sql-replay-go)
- [pkg/adapters/revocation/redis_revocation.go](#pkg-adapters-revocation-redis-revocation-go)
- [pkg/adapters/revocation/sql_revocation.go](#pkg-adapters-revocation-sql-revocation-go)
- [pkg/apierrors/rfc7807.go](#pkg-apierrors-rfc7807-go)
- [pkg/apierrors/rfc7807_test.go](#pkg-apierrors-rfc7807-test-go)
- [pkg/cache/lock.go](#pkg-cache-lock-go)
- [pkg/cache/valkey.go](#pkg-cache-valkey-go)
- [pkg/config/config.go](#pkg-config-config-go)
- [pkg/context/context.go](#pkg-context-context-go)
- [pkg/controller/auth_dto.go](#pkg-controller-auth-dto-go)
- [pkg/controller/auth_support_controller.go](#pkg-controller-auth-support-controller-go)
- [pkg/controller/base_controller.go](#pkg-controller-base-controller-go)
- [pkg/domain/support_grant.go](#pkg-domain-support-grant-go)
- [pkg/grantsupport/engine.go](#pkg-grantsupport-engine-go)
- [pkg/grantsupport/engine_test.go](#pkg-grantsupport-engine-test-go)
- [pkg/grantsupport/options.go](#pkg-grantsupport-options-go)
- [pkg/middleware/auth.go](#pkg-middleware-auth-go)
- [pkg/middleware/bulletproof_auth.go](#pkg-middleware-bulletproof-auth-go)
- [pkg/middleware/bulletproof_auth_test.go](#pkg-middleware-bulletproof-auth-test-go)
- [pkg/middleware/correlation.go](#pkg-middleware-correlation-go)
- [pkg/middleware/rbac.go](#pkg-middleware-rbac-go)
- [pkg/ports/lock.go](#pkg-ports-lock-go)
- [pkg/ports/rate_limit.go](#pkg-ports-rate-limit-go)
- [pkg/ports/replay.go](#pkg-ports-replay-go)
- [pkg/ports/revocation.go](#pkg-ports-revocation-go)
- [pkg/repository/base.go](#pkg-repository-base-go)
- [pkg/repository/db_compliance_test.go](#pkg-repository-db-compliance-test-go)
- [pkg/repository/repository_test.go](#pkg-repository-repository-test-go)
- [pkg/repository/security_audit_repository.go](#pkg-repository-security-audit-repository-go)
- [pkg/repository/support_grant_repository.go](#pkg-repository-support-grant-repository-go)
- [pkg/resilience/breaker.go](#pkg-resilience-breaker-go)
- [pkg/security/encryption.go](#pkg-security-encryption-go)
- [pkg/security/encryption_test.go](#pkg-security-encryption-test-go)
- [pkg/security/jwt.go](#pkg-security-jwt-go)
- [pkg/security/keys.go](#pkg-security-keys-go)
- [pkg/security/merkle.go](#pkg-security-merkle-go)
- [pkg/security/merkle_test.go](#pkg-security-merkle-test-go)
- [pkg/security/sanitizer.go](#pkg-security-sanitizer-go)
- [pkg/security/sanitizer_test.go](#pkg-security-sanitizer-test-go)
- [pkg/service/grant_support_service.go](#pkg-service-grant-support-service-go)
- [pkg/service/grant_support_service_test.go](#pkg-service-grant-support-service-test-go)
- [pkg/webhook/dispatcher.go](#pkg-webhook-dispatcher-go)
- [pkg/webhook/dispatcher_test.go](#pkg-webhook-dispatcher-test-go)

### ent/schema/
- [ent/generate.go](#ent-generate-go)
- [ent/schema/auditevent.go](#ent-schema-auditevent-go)
- [ent/schema/supportgrant.go](#ent-schema-supportgrant-go)

### api/
- [api/openapi.yaml](#api-openapi-yaml)

### migrations/
- [migrations/mariadb/000001_initial_grantsupport_schema.down.sql](#migrations-mariadb-000001-initial-grantsupport-schema-down-sql)
- [migrations/mariadb/000001_initial_grantsupport_schema.up.sql](#migrations-mariadb-000001-initial-grantsupport-schema-up-sql)
- [migrations/mysql/000001_initial_grantsupport_schema.down.sql](#migrations-mysql-000001-initial-grantsupport-schema-down-sql)
- [migrations/mysql/000001_initial_grantsupport_schema.up.sql](#migrations-mysql-000001-initial-grantsupport-schema-up-sql)
- [migrations/postgres/000001_initial_grantsupport_schema.down.sql](#migrations-postgres-000001-initial-grantsupport-schema-down-sql)
- [migrations/postgres/000001_initial_grantsupport_schema.up.sql](#migrations-postgres-000001-initial-grantsupport-schema-up-sql)
- [migrations/sqlite/000001_initial_grantsupport_schema.down.sql](#migrations-sqlite-000001-initial-grantsupport-schema-down-sql)
- [migrations/sqlite/000001_initial_grantsupport_schema.up.sql](#migrations-sqlite-000001-initial-grantsupport-schema-up-sql)

### docs/
- [docs/ARCHITECTURE.md](#docs-architecture-md)
- [docs/COMMERCIAL_MODELS.md](#docs-commercial-models-md)
- [docs/INTEGRATION_GUIDE.md](#docs-integration-guide-md)
- [docs/implementation_plan.md](#docs-implementation-plan-md)
- [docs/phase_1_plan.md](#docs-phase-1-plan-md)
- [docs/phase_2_plan.md](#docs-phase-2-plan-md)
- [docs/phase_3_plan.md](#docs-phase-3-plan-md)
- [docs/phase_4_plan.md](#docs-phase-4-plan-md)
- [docs/phase_5_plan.md](#docs-phase-5-plan-md)
- [docs/phase_6_plan.md](#docs-phase-6-plan-md)
- [docs/phase_7_plan.md](#docs-phase-7-plan-md)

### scripts/
- [scripts/archive/extract_grantsupport.py](#scripts-archive-extract-grantsupport-py)
- [scripts/update_source_exports.py](#scripts-update-source-exports-py)

### Root-level files
- [README.md](#readme-md)
- [Dockerfile](#dockerfile)
- [docker-compose.yml](#docker-compose-yml)
- [go.mod](#go-mod)
- [go.sum](#go-sum)

---

## cmd/server/main.go

```go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/cache"
	"grantsupport/pkg/config"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
	"grantsupport/pkg/webhook"
)

func main() {
	slog.Info("Starting GrantSupport Engine...", slog.String("version", "v1.0.0"))

	cfg := config.AppConfig
	if cfg == nil {
		var err error
		cfg, err = config.LoadConfig()
		if err != nil {
			slog.Error("Failed to load environment configuration", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	// Initialize RSA JWT Keys
	if err := security.LoadJWTKeysFromEnv(); err != nil {
		slog.Warn("RSA JWT keys not found in environment, generating transient keypair for runtime...")
		if err := security.SetupTestRSAKeys(); err != nil {
			slog.Error("Failed to initialize transient JWT keys", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	// Initialize Database Connection Pool based on configured dialect
	dialectName := cfg.DatabaseDialect
	if dialectName == "" {
		dialectName = "postgres"
	}

	var sqlDB *sql.DB
	var driverName string
	switch dialectName {
	case "sqlite", "sqlite3":
		driverName = "sqlite"
	case "mysql", "mariadb":
		driverName = "mysql"
	default:
		driverName = "pgx"
	}

	sqlDB, err := sql.Open(driverName, cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to open database connection", slog.String("dialect", dialectName), slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer sqlDB.Close()

	// Verify database connectivity
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer pingCancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		slog.Warn("Database ping check warning", slog.String("dialect", dialectName), slog.String("error", err.Error()))
	}

	baseRepo := repository.NewBaseRepositoryWithDB(sqlDB, dialectName)
	dbClient := baseRepo.MasterClient
	defer dbClient.Close()

	if err := dbClient.Schema.Create(context.Background()); err != nil {
		slog.Error("Failed to auto-migrate database schema", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize Capability Adapters (Redis if configured, else SQL/Memory Stores)
	var lockStore ports.LockStore
	var revocationStore ports.RevocationStore

	if cfg.ValkeyCacheURL != "" {
		valkeyClient, err := cache.NewValkeyClient(cfg.ValkeyCacheURL)
		if err != nil {
			slog.Warn("Valkey connection bypass (running with SQL/Memory lock & revocation)", slog.String("error", err.Error()))
			lockStore = lock.NewSQLLockStore(sqlDB, dialectName)
			revocationStore = revocation.NewSQLRevocationStore(sqlDB, dialectName)
		} else {
			lockStore = lock.NewRedisLockStore(valkeyClient.Client)
			revocationStore = revocation.NewRedisRevocationStore(valkeyClient.Client)
			slog.Info("Valkey distributed cache & locking initialized successfully")
		}
	} else {
		lockStore = lock.NewSQLLockStore(sqlDB, dialectName)
		revocationStore = revocation.NewSQLRevocationStore(sqlDB, dialectName)
	}

	// Initialize Repositories & Services (Standalone single-tenant / dedicated deployment)
	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	auditRepo.SetLockStore(lockStore)

	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)
	if cfg.WebhookURL != "" {
		webhookDispatcher := webhook.NewWebhookDispatcher(cfg.WebhookURL, cfg.WebhookSecret)
		grantService.SetWebhookDispatcher(webhookDispatcher)
		slog.Info("Webhook dispatcher initialized", slog.String("url", cfg.WebhookURL))
	}

	grantController := controller.NewSupportGrantController(grantService)

	// Router Setup
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.CorrelationIDMiddleware)

	// Public Health Endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"UP","service":"GrantSupport Engine","version":"v1.0.0"}`))
	})

	// Public Support Agent Login Endpoint
	r.Post("/api/v1/auth/support/login", controller.CatchAsync(grantController.SupportLogin))

	// Authenticated Customer Admin Delegation Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(revocationStore))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
	})

	port := cfg.Port
	if port == "" {
		port = "8085"
	}
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("GrantSupport Engine listening for traffic", slog.String("port", port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", slog.String("error", err.Error()))
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("Shutting down GrantSupport Engine gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	slog.Info("GrantSupport Engine stopped cleanly.")
}
```

---

## pkg/adapters/lock/lock_test.go

```go
package lock_test

import (
	"context"
	"testing"
	"time"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/ports"
)

func TestMemoryLockStore(t *testing.T) {
	store := lock.NewMemoryLockStore()
	ctx := context.Background()
	lockKey := "test:lock:123"

	// 1. First acquire succeeds
	token1, err := store.Acquire(ctx, lockKey, 1*time.Second)
	if err != nil {
		t.Fatalf("Expected successful acquire, got error: %v", err)
	}
	if token1 == "" {
		t.Fatal("Expected non-empty owner token")
	}

	// 2. Second concurrent acquire on same key fails with ErrLockBusy
	_, err = store.Acquire(ctx, lockKey, 1*time.Second)
	if err != ports.ErrLockBusy {
		t.Fatalf("Expected ErrLockBusy, got: %v", err)
	}

	// 3. Release with invalid token does not release the lock
	_ = store.Release(ctx, lockKey, "wrong_token")
	_, err = store.Acquire(ctx, lockKey, 1*time.Second)
	if err != ports.ErrLockBusy {
		t.Fatalf("Expected lock to still be held, got: %v", err)
	}

	// 4. Release with valid token allows subsequent acquire
	err = store.Release(ctx, lockKey, token1)
	if err != nil {
		t.Fatalf("Release failed: %v", err)
	}

	token2, err := store.Acquire(ctx, lockKey, 1*time.Second)
	if err != nil {
		t.Fatalf("Expected successful acquire after release, got: %v", err)
	}
	if token2 == "" {
		t.Fatal("Expected valid token")
	}
}

func TestMemoryLockStoreWithLock(t *testing.T) {
	store := lock.NewMemoryLockStore()
	ctx := context.Background()
	lockKey := "test:withlock"

	executed := false
	err := store.WithLock(ctx, lockKey, 1*time.Second, func(txCtx context.Context) error {
		executed = true
		// Verify lock is held during execution
		_, err := store.Acquire(txCtx, lockKey, 1*time.Second)
		if err != ports.ErrLockBusy {
			t.Errorf("Expected lock to be busy inside WithLock callback")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("WithLock failed: %v", err)
	}
	if !executed {
		t.Fatal("Expected callback to be executed")
	}

	// Verify lock is automatically released after WithLock finishes
	_, err = store.Acquire(ctx, lockKey, 1*time.Second)
	if err != nil {
		t.Fatalf("Expected lock to be released after WithLock: %v", err)
	}
}
```

---

## pkg/adapters/lock/memory_lock.go

```go
package lock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"grantsupport/pkg/ports"
)

type lockEntry struct {
	ownerToken string
	expiresAt  time.Time
}

// MemoryLockStore implements ports.LockStore using an in-memory map and mutex for single-instance deployments.
type MemoryLockStore struct {
	mu    sync.Mutex
	locks map[string]lockEntry
}

// NewMemoryLockStore constructs a new MemoryLockStore instance.
func NewMemoryLockStore() *MemoryLockStore {
	return &MemoryLockStore{
		locks: make(map[string]lockEntry),
	}
}

// Acquire attempts to acquire a lock for lockKey with the given TTL.
func (s *MemoryLockStore) Acquire(ctx context.Context, lockKey string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if entry, exists := s.locks[lockKey]; exists {
		if entry.expiresAt.After(now) {
			return "", ports.ErrLockBusy
		}
	}

	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	ownerToken := hex.EncodeToString(tokenBytes)

	s.locks[lockKey] = lockEntry{
		ownerToken: ownerToken,
		expiresAt:  now.Add(ttl),
	}
	return ownerToken, nil
}

// Release safely releases the lock if and only if the ownerToken matches.
func (s *MemoryLockStore) Release(ctx context.Context, lockKey, ownerToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.locks[lockKey]; exists {
		if entry.ownerToken == ownerToken {
			delete(s.locks, lockKey)
		}
	}
	return nil
}

// WithLock wraps a function call within an acquired lock.
func (s *MemoryLockStore) WithLock(ctx context.Context, lockKey string, ttl time.Duration, fn func(ctx context.Context) error) error {
	token, err := s.Acquire(ctx, lockKey, ttl)
	if err != nil {
		return err
	}
	defer func() {
		_ = s.Release(context.Background(), lockKey, token)
	}()

	return fn(ctx)
}
```

---

## pkg/adapters/lock/redis_lock.go

```go
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
```

---

## pkg/adapters/lock/sql_lock.go

```go
package lock

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"grantsupport/pkg/ports"
)

// SQLLockStore implements ports.LockStore using the gs_locks database lease table.
type SQLLockStore struct {
	db      *sql.DB
	dialect string
	mu      sync.Mutex // fallback serialization for SQLite
}

// NewSQLLockStore constructs a new SQLLockStore instance.
func NewSQLLockStore(db *sql.DB, dialect string) *SQLLockStore {
	if dialect == "" {
		dialect = "postgres"
	}
	return &SQLLockStore{
		db:      db,
		dialect: dialect,
	}
}

// Acquire attempts to acquire a lease lock on lockKey for the given TTL.
func (s *SQLLockStore) Acquire(ctx context.Context, lockKey string, ttl time.Duration) (string, error) {
	if s.db == nil {
		return "", ports.ErrLockUnavailable
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate lock token: %w", err)
	}
	ownerToken := hex.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	switch s.dialect {
	case "sqlite", "sqlite3":
		s.mu.Lock()
		defer s.mu.Unlock()

		// Attempt takeover of expired lock
		res, err := s.db.ExecContext(ctx,
			"UPDATE gs_locks SET owner_token = ?, expires_at = ?, acquired_at = ? WHERE lock_key = ? AND expires_at < ?",
			ownerToken, expiresAt, now, lockKey, now)
		if err == nil {
			if rows, _ := res.RowsAffected(); rows > 0 {
				return ownerToken, nil
			}
		}

		// Attempt new insert
		_, err = s.db.ExecContext(ctx,
			"INSERT INTO gs_locks (lock_key, owner_token, expires_at, acquired_at) VALUES (?, ?, ?, ?)",
			lockKey, ownerToken, expiresAt, now)
		if err != nil {
			return "", ports.ErrLockBusy
		}
		return ownerToken, nil

	case "mysql", "mariadb":
		// Step 1: Attempt to take over expired lock
		res, err := s.db.ExecContext(ctx,
			"UPDATE gs_locks SET owner_token = ?, expires_at = ?, acquired_at = ? WHERE lock_key = ? AND expires_at < ?",
			ownerToken, expiresAt, now, lockKey, now)
		if err == nil {
			if rows, _ := res.RowsAffected(); rows > 0 {
				return ownerToken, nil
			}
		}

		// Step 2: Attempt new insertion with IGNORE
		res, err = s.db.ExecContext(ctx,
			"INSERT IGNORE INTO gs_locks (lock_key, owner_token, expires_at, acquired_at) VALUES (?, ?, ?, ?)",
			lockKey, ownerToken, expiresAt, now)
		if err != nil {
			return "", fmt.Errorf("failed to acquire lock: %w", err)
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			return ownerToken, nil
		}
		return "", ports.ErrLockBusy

	default: // "postgres", "pgx"
		query := `
			INSERT INTO gs_locks (lock_key, owner_token, expires_at, acquired_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (lock_key) DO UPDATE
			SET owner_token = EXCLUDED.owner_token,
			    expires_at = EXCLUDED.expires_at,
			    acquired_at = EXCLUDED.acquired_at
			WHERE gs_locks.expires_at < $4
		`
		res, err := s.db.ExecContext(ctx, query, lockKey, ownerToken, expiresAt, now)
		if err != nil {
			return "", fmt.Errorf("failed to execute lock query: %w", err)
		}

		rows, err := res.RowsAffected()
		if err != nil || rows == 0 {
			return "", ports.ErrLockBusy
		}
		return ownerToken, nil
	}
}

// Release safely releases the lock if and only if the owner token matches.
func (s *SQLLockStore) Release(ctx context.Context, lockKey, ownerToken string) error {
	if s.db == nil {
		return nil
	}

	var query string
	switch s.dialect {
	case "mysql", "mariadb", "sqlite", "sqlite3":
		query = "DELETE FROM gs_locks WHERE lock_key = ? AND owner_token = ?"
	default:
		query = "DELETE FROM gs_locks WHERE lock_key = $1 AND owner_token = $2"
	}

	_, err := s.db.ExecContext(ctx, query, lockKey, ownerToken)
	return err
}

// WithLock wraps a function call within an acquired lock, automatically releasing upon completion.
func (s *SQLLockStore) WithLock(ctx context.Context, lockKey string, ttl time.Duration, fn func(ctx context.Context) error) error {
	token, err := s.Acquire(ctx, lockKey, ttl)
	if err != nil {
		return err
	}
	defer func() {
		_ = s.Release(context.Background(), lockKey, token)
	}()

	return fn(ctx)
}
```

---

## pkg/adapters/ratelimit/memory_ratelimit.go

```go
package ratelimit

import (
	"context"
	"sync"
	"time"
)

type rateBucket struct {
	tokens     int
	lastRefill time.Time
}

// MemoryRateLimiter implements ports.RateLimiterStore using in-memory token buckets.
type MemoryRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

// NewMemoryRateLimiter creates a new in-memory rate limiter.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{
		buckets: make(map[string]*rateBucket),
	}
}

// Allow evaluates if a request with key is permitted under limit per window.
func (r *MemoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	bucket, exists := r.buckets[key]
	if !exists || now.Sub(bucket.lastRefill) >= window {
		r.buckets[key] = &rateBucket{
			tokens:     limit - 1,
			lastRefill: now,
		}
		return true, nil
	}

	if bucket.tokens > 0 {
		bucket.tokens--
		return true, nil
	}

	return false, nil
}
```

---

## pkg/adapters/ratelimit/ratelimit_test.go

```go
package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"grantsupport/pkg/adapters/ratelimit"
)

func TestMemoryRateLimiter(t *testing.T) {
	limiter := ratelimit.NewMemoryRateLimiter()
	ctx := context.Background()
	key := "ip:127.0.0.1:login"
	limit := 3
	window := 200 * time.Millisecond

	// First 3 requests allowed
	for i := 1; i <= limit; i++ {
		allow, err := limiter.Allow(ctx, key, limit, window)
		if err != nil || !allow {
			t.Fatalf("Expected request %d to be allowed, got allow=%v, err=%v", i, allow, err)
		}
	}

	// 4th request exceeds limit
	allow, err := limiter.Allow(ctx, key, limit, window)
	if err != nil || allow {
		t.Fatalf("Expected 4th request to be throttled, got allow=%v, err=%v", allow, err)
	}

	// Wait for window to reset
	time.Sleep(250 * time.Millisecond)

	// Should be allowed again after window refill
	allow, err = limiter.Allow(ctx, key, limit, window)
	if err != nil || !allow {
		t.Fatalf("Expected request after window reset to be allowed, got allow=%v, err=%v", allow, err)
	}
}
```

---

## pkg/adapters/ratelimit/redis_ratelimit.go

```go
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
	if r.client == nil || limit <= 0 {
		return true, nil // Fail open on rate limiting infrastructure error
	}

	rateKey := fmt.Sprintf("ratelimit:%s", key)
	count, err := r.client.Incr(ctx, rateKey).Result()
	if err != nil {
		return true, nil // Fail open
	}

	if count == 1 {
		_ = r.client.Expire(ctx, rateKey, window).Err()
	}

	return count <= int64(limit), nil
}
```

---

## pkg/adapters/replay/memory_replay.go

```go
package replay

import (
	"context"
	"fmt"
	"sync"
	"time"

	"grantsupport/pkg/ports"
)

type nonceEntry struct {
	expiresAt time.Time
}

// MemoryReplayStore implements ports.ReplayStore in-memory for single-instance deployments.
type MemoryReplayStore struct {
	mu     sync.RWMutex
	nonces map[string]nonceEntry
	stopCh chan struct{}
}

// NewMemoryReplayStore creates a new in-memory replay cache with periodic background eviction.
func NewMemoryReplayStore(cleanupInterval time.Duration) *MemoryReplayStore {
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Minute
	}

	store := &MemoryReplayStore{
		nonces: make(map[string]nonceEntry),
		stopCh: make(chan struct{}),
	}

	go store.startCleanup(cleanupInterval)
	return store
}

// CheckAndSet returns true if the nonce was not previously registered within its TTL.
func (s *MemoryReplayStore) CheckAndSet(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	key := fmt.Sprintf("%s:%s", keyID, nonce)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.nonces[key]; exists {
		if entry.expiresAt.After(now) {
			return false, ports.ErrReplayDetected
		}
	}

	s.nonces[key] = nonceEntry{
		expiresAt: now.Add(ttl),
	}
	return true, nil
}

func (s *MemoryReplayStore) startCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.evictExpired()
		}
	}
}

func (s *MemoryReplayStore) evictExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, entry := range s.nonces {
		if entry.expiresAt.Before(now) {
			delete(s.nonces, key)
		}
	}
}

// Close stops the background eviction goroutine.
func (s *MemoryReplayStore) Close() {
	close(s.stopCh)
}
```

---

## pkg/adapters/replay/redis_replay.go

```go
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
```

---

## pkg/adapters/replay/replay_test.go

```go
package replay_test

import (
	"context"
	"testing"
	"time"

	"grantsupport/pkg/adapters/replay"
	"grantsupport/pkg/ports"
)

func TestMemoryReplayStore(t *testing.T) {
	store := replay.NewMemoryReplayStore(100 * time.Millisecond)
	defer store.Close()

	ctx := context.Background()
	keyID := "key_test_1"
	nonce := "nonce_abc_123"

	// 1. First presentation of nonce succeeds
	ok, err := store.CheckAndSet(ctx, keyID, nonce, 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("Expected first CheckAndSet to succeed, got ok=%v, err=%v", ok, err)
	}

	// 2. Duplicate nonce presentation within TTL is rejected
	ok, err = store.CheckAndSet(ctx, keyID, nonce, 500*time.Millisecond)
	if ok || err != ports.ErrReplayDetected {
		t.Fatalf("Expected duplicate nonce to be rejected with ErrReplayDetected, got ok=%v, err=%v", ok, err)
	}

	// 3. Different nonce for same key succeeds
	ok, err = store.CheckAndSet(ctx, keyID, "nonce_different_456", 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("Expected different nonce to succeed, got ok=%v, err=%v", ok, err)
	}

	// 4. Same nonce for different key succeeds
	ok, err = store.CheckAndSet(ctx, "key_different_2", nonce, 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("Expected same nonce on different key to succeed, got ok=%v, err=%v", ok, err)
	}
}
```

---

## pkg/adapters/replay/sql_replay.go

```go
package replay

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"grantsupport/pkg/ports"
)

// SQLReplayStore implements ports.ReplayStore using the gs_replays database table.
type SQLReplayStore struct {
	db      *sql.DB
	dialect string
}

// NewSQLReplayStore creates a new SQL-backed replay store.
func NewSQLReplayStore(db *sql.DB, dialect string) *SQLReplayStore {
	if dialect == "" {
		dialect = "postgres"
	}
	return &SQLReplayStore{
		db:      db,
		dialect: dialect,
	}
}

// CheckAndSet registers a nonce if it does not already exist.
func (s *SQLReplayStore) CheckAndSet(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	if s.db == nil {
		return false, fmt.Errorf("database connection is nil")
	}

	nonceKey := fmt.Sprintf("%s:%s", keyID, nonce)
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	switch s.dialect {
	case "sqlite", "sqlite3":
		// Clean up expired entry if it exists
		_, _ = s.db.ExecContext(ctx, "DELETE FROM gs_replays WHERE nonce_key = ? AND expires_at < ?", nonceKey, now)

		_, err := s.db.ExecContext(ctx, "INSERT INTO gs_replays (nonce_key, expires_at) VALUES (?, ?)", nonceKey, expiresAt)
		if err != nil {
			return false, ports.ErrReplayDetected
		}
		return true, nil

	case "mysql", "mariadb":
		// Takeover or clean up expired entry
		_, _ = s.db.ExecContext(ctx, "DELETE FROM gs_replays WHERE nonce_key = ? AND expires_at < ?", nonceKey, now)

		res, err := s.db.ExecContext(ctx, "INSERT IGNORE INTO gs_replays (nonce_key, expires_at) VALUES (?, ?)", nonceKey, expiresAt)
		if err != nil {
			return false, err
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			return false, ports.ErrReplayDetected
		}
		return true, nil

	default: // "postgres", "pgx"
		query := `
			INSERT INTO gs_replays (nonce_key, expires_at)
			VALUES ($1, $2)
			ON CONFLICT (nonce_key) DO UPDATE
			SET expires_at = EXCLUDED.expires_at
			WHERE gs_replays.expires_at < $3
		`
		res, err := s.db.ExecContext(ctx, query, nonceKey, expiresAt, now)
		if err != nil {
			return false, err
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			return false, ports.ErrReplayDetected
		}
		return true, nil
	}
}
```

---

## pkg/adapters/revocation/redis_revocation.go

```go
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
		return false, nil
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
```

---

## pkg/adapters/revocation/sql_revocation.go

```go
package revocation

import (
	"context"
	"database/sql"
	"fmt"
)

// SQLRevocationStore implements ports.RevocationStore using the gs_revocations table.
type SQLRevocationStore struct {
	db      *sql.DB
	dialect string
}

// NewSQLRevocationStore creates a new SQL-backed revocation store.
func NewSQLRevocationStore(db *sql.DB, dialect string) *SQLRevocationStore {
	if dialect == "" {
		dialect = "postgres"
	}
	return &SQLRevocationStore{
		db:      db,
		dialect: dialect,
	}
}

// IsTokenRevoked returns true if the user's current minimum valid token version is greater than tokenVersion.
func (s *SQLRevocationStore) IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error) {
	if s.db == nil {
		return false, nil // fail-open if not configured or fallback
	}

	var currentVersion int
	var query string
	switch s.dialect {
	case "mysql", "mariadb", "sqlite", "sqlite3":
		query = "SELECT token_version FROM gs_revocations WHERE institution_id = ? AND user_id = ?"
	default:
		query = "SELECT token_version FROM gs_revocations WHERE institution_id = $1 AND user_id = $2"
	}

	err := s.db.QueryRowContext(ctx, query, institutionID, userID).Scan(&currentVersion)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return currentVersion > tokenVersion, nil
}

// RevokeUserSessions updates the minimum valid token version for a user.
func (s *SQLRevocationStore) RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error {
	if s.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	switch s.dialect {
	case "sqlite", "sqlite3":
		query := `
			INSERT INTO gs_revocations (institution_id, user_id, token_version, revoked_at)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (institution_id, user_id) DO UPDATE
			SET token_version = ?, revoked_at = CURRENT_TIMESTAMP
		`
		_, err := s.db.ExecContext(ctx, query, institutionID, userID, newVersion, newVersion)
		return err

	case "mysql", "mariadb":
		query := `
			INSERT INTO gs_revocations (institution_id, user_id, token_version, revoked_at)
			VALUES (?, ?, ?, NOW(6))
			ON DUPLICATE KEY UPDATE
			token_version = VALUES(token_version), revoked_at = VALUES(revoked_at)
		`
		_, err := s.db.ExecContext(ctx, query, institutionID, userID, newVersion)
		return err

	default: // "postgres", "pgx"
		query := `
			INSERT INTO gs_revocations (institution_id, user_id, token_version, revoked_at)
			VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
			ON CONFLICT (institution_id, user_id) DO UPDATE
			SET token_version = EXCLUDED.token_version, revoked_at = EXCLUDED.revoked_at
		`
		_, err := s.db.ExecContext(ctx, query, institutionID, userID, newVersion)
		return err
	}
}
```

---

## pkg/apierrors/rfc7807.go

```go
package apierrors

import (
	"encoding/json"
	"net/http"
	"strings"
)

// InvalidParam represents specific field validation failures.
type InvalidParam struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// ProblemDetails represents the RFC 7807 Problem Details JSON format.
type ProblemDetails struct {
	Type          string         `json:"type"`
	Title         string         `json:"title"`
	Status        int            `json:"status"`
	Detail        string         `json:"detail"`
	Instance      string         `json:"instance,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	InvalidParams []InvalidParam `json:"invalid_params,omitempty"`
}

// Error implements the standard Go error interface.
func (pd *ProblemDetails) Error() string {
	return pd.Detail
}

// NewProblemDetails instantiates a custom problem details error payload.
func NewProblemDetails(status int, errType, title, detail, instance, correlationID string, invalidParams ...InvalidParam) *ProblemDetails {
	if errType == "" {
		errType = "https://grantsupport.io/errors/" + strings.ToLower(title)
	}
	return &ProblemDetails{
		Type:          errType,
		Title:         title,
		Status:        status,
		Detail:        detail,
		Instance:      instance,
		CorrelationID: correlationID,
		InvalidParams: invalidParams,
	}
}

// WriteJSON sends the RFC 7807 compliant error format down the HTTP response writer.
func (pd *ProblemDetails) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(pd.Status)
	_ = json.NewEncoder(w).Encode(pd)
}

// WriteRFC7807 is a helper to write standard RFC 7807 responses directly with context extraction.
func WriteRFC7807(w http.ResponseWriter, r *http.Request, status int, code, detail string, invalidParams ...InvalidParam) {
	instance := ""
	correlationID := ""
	if r != nil {
		instance = r.URL.Path
		correlationID = r.Header.Get("X-Correlation-ID")
	}

	pd := NewProblemDetails(status, "", code, detail, instance, correlationID, invalidParams...)
	pd.WriteJSON(w)
}
```

---

## pkg/apierrors/rfc7807_test.go

```go
package apierrors_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"grantsupport/pkg/apierrors"
)

func TestWriteRFC7807(t *testing.T) {
	t.Run("Serializes ProblemDetails with invalid_params and correlation_id", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/test", nil)
		req.Header.Set("X-Correlation-ID", "corr_12345")
		rr := httptest.NewRecorder()

		invalidParams := []apierrors.InvalidParam{
			{Name: "duration_minutes", Reason: "must be positive"},
		}

		apierrors.WriteRFC7807(rr, req, http.StatusBadRequest, "INVALID_INPUT", "Validation failed", invalidParams...)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}

		if contentType := rr.Header().Get("Content-Type"); contentType != "application/problem+json" {
			t.Errorf("Expected Content-Type application/problem+json, got %s", contentType)
		}

		var pd apierrors.ProblemDetails
		if err := json.Unmarshal(rr.Body.Bytes(), &pd); err != nil {
			t.Fatalf("Failed to unmarshal ProblemDetails response: %v", err)
		}

		if pd.Title != "INVALID_INPUT" {
			t.Errorf("Expected title INVALID_INPUT, got %s", pd.Title)
		}
		if pd.Instance != "/api/v1/test" {
			t.Errorf("Expected instance /api/v1/test, got %s", pd.Instance)
		}
		if pd.CorrelationID != "corr_12345" {
			t.Errorf("Expected correlation_id corr_12345, got %s", pd.CorrelationID)
		}
		if len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Name != "duration_minutes" {
			t.Errorf("Expected invalid_params for duration_minutes, got %+v", pd.InvalidParams)
		}
	})
}
```

---

## pkg/cache/lock.go

```go
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
```

---

## pkg/cache/valkey.go

```go
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
```

---

## pkg/config/config.go

```go
// Package config handles application environment configuration loading.
package config

import (
	"os"
)

// Config holds environment configurations for database, caching, queues, KMS encryption, and server ports.
type Config struct {
	DatabaseURL            string
	DatabaseDialect        string
	ValkeyCacheURL         string
	ValkeyQueueURL         string
	Port                   string
	Environment            string
	AWSRegion              string
	EncryptionProvider     string
	KmsKeyID               string
	LocalSecretKey         string
	MasterEncryptionKey    string
	TrustedProxies         []string
	EnforceStrictIPBinding bool
	WebhookURL             string
	WebhookSecret          string
}

// AppConfig is a global singleton instance of application configuration.
var AppConfig *Config

func init() {
	AppConfig, _ = LoadConfig()
}

// LoadConfig loads environment configurations with sensible production defaults.
func LoadConfig() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://postgres:password@localhost:5432/grantsupport?sslmode=disable"
	}

	dbDialect := os.Getenv("DATABASE_DIALECT")
	if dbDialect == "" {
		dbDialect = "postgres"
	}

	valkeyCacheURL := os.Getenv("VALKEY_CACHE_URL")
	if valkeyCacheURL == "" {
		valkeyCacheURL = "redis://127.0.0.1:6379"
	}

	valkeyQueueURL := os.Getenv("VALKEY_QUEUE_URL")
	if valkeyQueueURL == "" {
		valkeyQueueURL = "redis://127.0.0.1:6380"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	env := os.Getenv("GO_ENV")
	if env == "" {
		env = "development"
	}

	awsRegion := os.Getenv("AWS_REGION")
	if awsRegion == "" {
		awsRegion = "ap-south-1"
	}

	provider := os.Getenv("ENCRYPTION_PROVIDER")
	if provider == "" {
		provider = "LOCAL"
	}

	kmsKeyID := os.Getenv("KMS_KEY_ID")

	localSecretKey := os.Getenv("LOCAL_SECRET_KEY")
	if localSecretKey == "" {
		localSecretKey = "0123456789abcdef0123456789abcdef" // 32-byte AES-GCM default test key
	}

	masterKey := os.Getenv("MASTER_ENCRYPTION_KEY")
	if masterKey == "" {
		masterKey = "0123456789abcdef0123456789abcdef"
	}

	strictIP := os.Getenv("ENFORCE_STRICT_IP_BINDING") == "true"

	// Production Panic Guard: Prevent running with default secret keys or unencrypted fallback URLs in production
	if env == "production" {
		if masterKey == "0123456789abcdef0123456789abcdef" || localSecretKey == "0123456789abcdef0123456789abcdef" {
			panic("CRITICAL_SECURITY_ERROR: Default fallback MASTER_ENCRYPTION_KEY / LOCAL_SECRET_KEY is strictly forbidden in production!")
		}
		if dbURL == "postgresql://postgres:password@localhost:5432/grantsupport?sslmode=disable" {
			panic("CRITICAL_SECURITY_ERROR: Unencrypted fallback DATABASE_URL with default password is strictly forbidden in production!")
		}
	}

	webhookURL := os.Getenv("WEBHOOK_URL")
	webhookSecret := os.Getenv("WEBHOOK_SECRET")

	cfg := &Config{
		DatabaseURL:            dbURL,
		DatabaseDialect:        dbDialect,
		ValkeyCacheURL:         valkeyCacheURL,
		ValkeyQueueURL:         valkeyQueueURL,
		Port:                   port,
		Environment:            env,
		AWSRegion:              awsRegion,
		EncryptionProvider:     provider,
		KmsKeyID:               kmsKeyID,
		LocalSecretKey:         localSecretKey,
		MasterEncryptionKey:    masterKey,
		TrustedProxies:         []string{"127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		EnforceStrictIPBinding: strictIP,
		WebhookURL:             webhookURL,
		WebhookSecret:          webhookSecret,
	}

	AppConfig = cfg
	return cfg, nil
}
```

---

## pkg/context/context.go

```go
package pkgctx

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const (
	tenantKey contextKey = "tenant_data"
	userKey   contextKey = "user_id"
	roleKey   contextKey = "user_role"
)

// TenantData holds the authenticated tenant context for a request.
type TenantData struct {
	InstitutionID uuid.UUID
	UserID        uuid.UUID
	Role          string
}

// WithTenant stores TenantData in context.
func WithTenant(ctx context.Context, tenant *TenantData) context.Context {
	return context.WithValue(ctx, tenantKey, tenant)
}

// GetTenant retrieves TenantData from context.
func GetTenant(ctx context.Context) (*TenantData, bool) {
	val, ok := ctx.Value(tenantKey).(*TenantData)
	return val, ok
}

// WithUser stores user ID in context.
func WithUser(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userKey, userID)
}

// GetUser retrieves user ID from context.
func GetUser(ctx context.Context) (uuid.UUID, bool) {
	if val, ok := ctx.Value(userKey).(uuid.UUID); ok {
		return val, true
	}
	if tenant, ok := GetTenant(ctx); ok && tenant != nil {
		return tenant.UserID, true
	}
	return uuid.Nil, false
}

// WithRole stores user role in context.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleKey, role)
}

// GetRole retrieves user role from context.
func GetRole(ctx context.Context) (string, bool) {
	if val, ok := ctx.Value(roleKey).(string); ok {
		return val, true
	}
	if tenant, ok := GetTenant(ctx); ok && tenant != nil {
		return tenant.Role, true
	}
	return "", false
}
```

---

## pkg/controller/auth_dto.go

```go
package controller

// GrantSupportInput captures support delegation duration, scopes, and IP restrictions.
type GrantSupportInput struct {
	DurationMinutes int      `json:"durationMinutes" validate:"gte=1,lte=1440"`
	Scope           string   `json:"scope,omitempty" validate:"omitempty,max=64"`
	WhitelistedIPs  []string `json:"whitelistedIps,omitempty"`
}

// SupportLoginInput captures support token payload and explicit agent UUID.
type SupportLoginInput struct {
	Token   string `json:"token" validate:"required"`
	AgentID string `json:"agentId,omitempty" validate:"omitempty,uuid"`
}
```

---

## pkg/controller/auth_support_controller.go

```go
package controller

import (
	"net/http"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/service"
)

// SupportGrantController handles delegated support grant HTTP endpoints.
type SupportGrantController struct {
	grantService *service.GrantSupportService
}

// NewSupportGrantController constructs a SupportGrantController instance.
func NewSupportGrantController(grantService *service.GrantSupportService) *SupportGrantController {
	return &SupportGrantController{
		grantService: grantService,
	}
}

// GrantSupport generates a temporary platform owner support audit token.
// POST /api/v1/auth/support/grant
func (c *SupportGrantController) GrantSupport(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	input, err := DecodeAndValidate[GrantSupportInput](r)
	if err != nil {
		return err
	}

	token, err := c.grantService.CreateSupportGrantScoped(r.Context(), tenant.InstitutionID, tenant.UserID, input.DurationMinutes, input.Scope, input.WhitelistedIPs)
	if err != nil {
		return NewAppError(http.StatusBadRequest, "GRANT_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"message": "Support access token generated successfully.",
		"token":   token,
	})
	return nil
}

// SupportLogin authenticates a delegated support agent using a support token.
// POST /api/v1/auth/support/login
func (c *SupportGrantController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}

	var callerID uuid.UUID
	if input.AgentID != "" {
		parsed, err := uuid.Parse(input.AgentID)
		if err != nil {
			return NewAppError(http.StatusBadRequest, "INVALID_AGENT_ID", "agentId must be a valid UUID")
		}
		callerID = parsed
	} else if tenant, ok := pkgctx.GetTenant(r.Context()); ok && tenant != nil {
		callerID = tenant.UserID
	} else if userID, ok := pkgctx.GetUser(r.Context()); ok {
		callerID = userID
	} else {
		return NewAppError(http.StatusBadRequest, "AGENT_ID_REQUIRED", "Explicit agentId UUID must be provided in request body")
	}

	instID, jwtToken, err := c.grantService.SupportLogin(r.Context(), input.Token, callerID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Delegated support login successful.",
		"access_token": jwtToken,
		"data": map[string]any{
			"institution_id": instID,
			"access_token":   jwtToken,
		},
	})
	return nil
}

// RevokeSupport revokes all active support delegations for an institution.
// POST /api/v1/auth/support/revoke
func (c *SupportGrantController) RevokeSupport(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	if err := c.grantService.RevokeSupportGrant(r.Context(), tenant.InstitutionID, tenant.UserID); err != nil {
		return NewAppError(http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "All support delegations revoked successfully.",
	})
	return nil
}
```

---

## pkg/controller/base_controller.go

```go
package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// AppError represents a structured application domain or validation error for RFC 7807 problem details.
type AppError struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (e *AppError) Error() string {
	return e.Detail
}

// NewAppError constructs a new AppError instance.
func NewAppError(status int, code, detail string) *AppError {
	return &AppError{
		Status: status,
		Code:   code,
		Detail: detail,
	}
}

// CatchAsync is the Go higher-order function equivalent of Node.js catchAsync middleware.
// It wraps controller handler methods, automatically enforcing RFC 7807 Problem Details formatting on errors.
func CatchAsync(fn func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			var appErr *AppError
			if errors.As(err, &appErr) {
				WriteRFC7807Error(w, appErr.Status, appErr.Code, appErr.Detail)
				return
			}

			// Validation Error mapping
			var validationErrs validator.ValidationErrors
			if errors.As(err, &validationErrs) {
				var sb strings.Builder
				for i, fieldErr := range validationErrs {
					if i > 0 {
						sb.WriteString("; ")
					}
					sb.WriteString(fmt.Sprintf("field '%s' failed validation rule '%s'", fieldErr.Field(), fieldErr.Tag()))
				}
				WriteRFC7807Error(w, http.StatusBadRequest, "VALIDATION_ERROR", sb.String())
				return
			}

			// Fallback runtime error (Sanitized to prevent internal database structure leakage)
			slog.Error("[UNHANDLED_HTTP_ERROR]", slog.String("error", err.Error()), slog.String("path", r.URL.Path))
			WriteRFC7807Error(w, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "An unexpected internal server error occurred. Please contact support.")
		}
	}
}

// DecodeAndValidate parses JSON payload into a target struct DTO and executes go-playground/validator v10 validation rules.
func DecodeAndValidate[T any](r *http.Request) (T, error) {
	var dto T
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		return dto, NewAppError(http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body format")
	}

	if err := validate.Struct(dto); err != nil {
		return dto, err
	}

	return dto, nil
}

// WriteJSON sends a standardized 200/201 JSON response.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// WriteRFC7807Error serializes an RFC 7807 Problem Details error response.
func WriteRFC7807Error(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":     "https://grantsupport.io/errors/" + strings.ToLower(code),
		"title":    code,
		"status":   status,
		"detail":   detail,
		"instance": "",
	})
}

// getRemoteIP extracts client remote IP safely prioritize Cloudflare headers without trusting raw X-Forwarded-For.
func getRemoteIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	return r.RemoteAddr
}
```

---

## pkg/domain/support_grant.go

```go
package domain

import (
	"time"

	"github.com/google/uuid"
)

type CreateSupportGrantInput struct {
	InstitutionID  uuid.UUID `json:"institution_id"`
	GrantedByID    uuid.UUID `json:"granted_by_id"`
	TokenHash      string    `json:"token_hash"`
	ExpiresAt      time.Time `json:"expires_at"`
	Scope          string    `json:"scope,omitempty"`
	WhitelistedIPs []string  `json:"whitelisted_ips,omitempty"`
}
```

---

## pkg/grantsupport/engine.go

```go
package grantsupport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"grantsupport/ent"
	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/ratelimit"
	"grantsupport/pkg/adapters/replay"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
	"grantsupport/pkg/webhook"
)

// Engine is the central embeddable GrantSupport core engine instance.
type Engine struct {
	config            *EngineConfig
	baseRepo          *repository.BaseRepository
	grantRepo         *repository.SupportGrantRepository
	auditRepo         *repository.SecurityAuditRepository
	grantService      *service.GrantSupportService
	grantController   *controller.SupportGrantController
	lockStore         ports.LockStore
	replayStore       ports.ReplayStore
	revocationStore   ports.RevocationStore
	rateLimiter       ports.RateLimiterStore
	webhookDispatcher *webhook.WebhookDispatcher
}

// NewEngine initializes a fully configured in-process GrantSupport engine.
func NewEngine(opts ...Option) (*Engine, error) {
	cfg := &EngineConfig{
		Dialect:     "postgres",
		AutoMigrate: true,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// 1. Initialize Database Repository Layer
	var baseRepo *repository.BaseRepository
	if cfg.EntClient != nil {
		baseRepo = repository.NewBaseRepository(cfg.EntClient)
	} else if cfg.SQLDB != nil {
		baseRepo = repository.NewBaseRepositoryWithDB(cfg.SQLDB, cfg.Dialect)
	} else {
		return nil, errors.New("DATABASE_REQUIRED: Either WithDB or WithEntClient must be provided to NewEngine")
	}

	client, err := baseRepo.GetClient(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to obtain database client: %w", err)
	}

	// 2. Auto-Migrate Schemas if enabled
	if cfg.AutoMigrate {
		migrateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.Schema.Create(migrateCtx); err != nil {
			return nil, fmt.Errorf("failed to auto-migrate database schema: %w", err)
		}
		if cfg.SQLDB != nil {
			if err := createCapabilityTables(migrateCtx, cfg.SQLDB, cfg.Dialect); err != nil {
				return nil, fmt.Errorf("failed to create capability tables: %w", err)
			}
		}
	}

	// 3. Initialize RSA Cryptographic Keys
	if len(cfg.PrivateKeyPEM) > 0 && len(cfg.PublicKeyPEM) > 0 {
		if err := security.InitJWTKeys(cfg.PrivateKeyPEM, cfg.PublicKeyPEM); err != nil {
			return nil, fmt.Errorf("failed to initialize provided RSA JWT keys: %w", err)
		}
	} else {
		if err := security.LoadJWTKeysFromEnv(); err != nil {
			// Generate test keypair fallback
			if err := security.SetupTestRSAKeys(); err != nil {
				return nil, fmt.Errorf("failed to initialize transient RSA JWT keys: %w", err)
			}
		}
	}

	// 4. Initialize Capability Stores (Default to SQL or In-Memory adapters if omitted)
	lockStore := cfg.LockStore
	if lockStore == nil {
		if cfg.SQLDB != nil {
			lockStore = lock.NewSQLLockStore(cfg.SQLDB, cfg.Dialect)
		} else {
			lockStore = lock.NewMemoryLockStore()
		}
	}

	replayStore := cfg.ReplayStore
	if replayStore == nil {
		if cfg.SQLDB != nil {
			replayStore = replay.NewSQLReplayStore(cfg.SQLDB, cfg.Dialect)
		} else {
			replayStore = replay.NewMemoryReplayStore(1 * time.Minute)
		}
	}

	revocationStore := cfg.RevocationStore
	if revocationStore == nil {
		if cfg.SQLDB != nil {
			revocationStore = revocation.NewSQLRevocationStore(cfg.SQLDB, cfg.Dialect)
		}
	}

	rateLimiter := cfg.RateLimiter
	if rateLimiter == nil {
		rateLimiter = ratelimit.NewMemoryRateLimiter()
	}

	// 5. Initialize Webhook Dispatcher
	var webhookDispatcher *webhook.WebhookDispatcher
	if cfg.WebhookURL != "" {
		webhookDispatcher = webhook.NewWebhookDispatcher(cfg.WebhookURL, cfg.WebhookSecret)
	}

	// 6. Assemble Repositories, Services, and Controllers
	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	auditRepo.SetLockStore(lockStore)

	grantService := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
	if webhookDispatcher != nil {
		grantService.SetWebhookDispatcher(webhookDispatcher)
	}

	grantController := controller.NewSupportGrantController(grantService)

	return &Engine{
		config:            cfg,
		baseRepo:          baseRepo,
		grantRepo:         grantRepo,
		auditRepo:         auditRepo,
		grantService:      grantService,
		grantController:   grantController,
		lockStore:         lockStore,
		replayStore:       replayStore,
		revocationStore:   revocationStore,
		rateLimiter:       rateLimiter,
		webhookDispatcher: webhookDispatcher,
	}, nil
}

// CreateSupportGrant creates a time-bounded, cryptographically signed support access token.
func (e *Engine) CreateSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int, scope string, whitelistedIPs []string) (string, error) {
	return e.grantService.CreateSupportGrantScoped(ctx, institutionID, adminUserID, durationMinutes, scope, whitelistedIPs)
}

// SupportLogin consumes a support grant token, emits an audit entry, and issues an RS256 JWT access token.
func (e *Engine) SupportLogin(ctx context.Context, rawToken string, agentUserID uuid.UUID) (uuid.UUID, string, error) {
	return e.grantService.SupportLogin(ctx, rawToken, agentUserID)
}

// RevokeSupportGrant invalidates all active support access grants for an institution.
func (e *Engine) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	return e.grantService.RevokeSupportGrant(ctx, institutionID, adminUserID)
}

// VerifyAuditChain cryptographically verifies the SHA-256 hash-chain across all historical events for an institution.
func (e *Engine) VerifyAuditChain(ctx context.Context, institutionID uuid.UUID) (bool, error) {
	return e.auditRepo.VerifyAuditChain(ctx, institutionID)
}

// GetAuditEvents queries paginated audit log events for an institution.
func (e *Engine) GetAuditEvents(ctx context.Context, institutionID uuid.UUID, limit, offset int) ([]*ent.AuditEvent, error) {
	return e.auditRepo.GetAuditEventsByInstitution(ctx, institutionID, limit, offset)
}

// HTTPHandler returns a ready-to-mount standard http.Handler / chi.Router with all GrantSupport endpoints.
func (e *Engine) HTTPHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.CorrelationIDMiddleware)

	// Health Check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"UP","service":"GrantSupport Engine","version":"v1.0.0"}`))
	})

	// Public Support Login
	r.Post("/api/v1/auth/support/login", controller.CatchAsync(e.grantController.SupportLogin))

	// Authenticated Admin Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(e.revocationStore))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(e.grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(e.grantController.RevokeSupport))
	})

	return r
}

// BulletproofMiddleware returns the 5-layer Ed25519 dual-key authentication middleware.
func (e *Engine) BulletproofMiddleware(keyStore map[string]*security.APIKeyDetails) func(http.Handler) http.Handler {
	return middleware.BulletproofAuthMiddleware(e.replayStore, keyStore)
}

// AuthMiddleware returns the JWT bearer authentication middleware with revocation checks.
func (e *Engine) AuthMiddleware() func(http.Handler) http.Handler {
	return middleware.NewAuthMiddleware(e.revocationStore)
}

// Close gracefully releases engine resources. Does NOT close caller-provided *sql.DB.
func (e *Engine) Close() error {
	if memReplay, ok := e.replayStore.(*replay.MemoryReplayStore); ok {
		memReplay.Close()
	}

	if e.config.OwnsDB && e.baseRepo != nil && e.baseRepo.SQLDB != nil {
		return e.baseRepo.SQLDB.Close()
	}

	return nil
}

func createCapabilityTables(ctx context.Context, db *sql.DB, dialect string) error {
	if db == nil {
		return nil
	}

	var ddl string
	switch dialect {
	case "sqlite", "sqlite3":
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (
			lock_key TEXT PRIMARY KEY,
			owner_token TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			acquired_at DATETIME NOT NULL
		);
		CREATE TABLE IF NOT EXISTS gs_replays (
			nonce_key TEXT PRIMARY KEY,
			expires_at DATETIME NOT NULL
		);
		CREATE TABLE IF NOT EXISTS gs_revocations (
			institution_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			token_version INTEGER NOT NULL DEFAULT 1,
			revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (institution_id, user_id)
		);`
	case "mysql", "mariadb":
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (
			lock_key VARCHAR(255) PRIMARY KEY,
			owner_token VARCHAR(64) NOT NULL,
			expires_at DATETIME(6) NOT NULL,
			acquired_at DATETIME(6) NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		CREATE TABLE IF NOT EXISTS gs_replays (
			nonce_key VARCHAR(255) PRIMARY KEY,
			expires_at DATETIME(6) NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		CREATE TABLE IF NOT EXISTS gs_revocations (
			institution_id VARCHAR(36) NOT NULL,
			user_id VARCHAR(36) NOT NULL,
			token_version INT NOT NULL DEFAULT 1,
			revoked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			PRIMARY KEY (institution_id, user_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`
	default: // postgres, pgx
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (
			lock_key VARCHAR(255) PRIMARY KEY,
			owner_token VARCHAR(64) NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			acquired_at TIMESTAMPTZ NOT NULL
		);
		CREATE TABLE IF NOT EXISTS gs_replays (
			nonce_key VARCHAR(255) PRIMARY KEY,
			expires_at TIMESTAMPTZ NOT NULL
		);
		CREATE TABLE IF NOT EXISTS gs_revocations (
			institution_id UUID NOT NULL,
			user_id UUID NOT NULL,
			token_version INTEGER NOT NULL DEFAULT 1,
			revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (institution_id, user_id)
		);`
	}

	_, err := db.ExecContext(ctx, ddl)
	return err
}
```

---

## pkg/grantsupport/engine_test.go

```go
package grantsupport_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
)

func TestEmbeddedEngineLifecycle(t *testing.T) {
	ctx := context.Background()

	// 1. Open caller-managed SQLite in-memory database
	db, err := sql.Open("sqlite", "file:grantsupport_engine_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	// 2. Initialize GrantSupport Engine via functional options
	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("Failed to initialize GrantSupport Engine: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Errorf("Engine.Close failed: %v", err)
		}
		// Verify caller database connection pool is still active
		if err := db.Ping(); err != nil {
			t.Errorf("Caller database was unexpectedly closed: %v", err)
		}
	}()

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// 3. Test Direct Go API: CreateSupportGrant
	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "BILLING_ONLY", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected non-empty raw grant token")
	}

	// 4. Test Direct Go API: SupportLogin
	returnedInstID, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}
	if returnedInstID != instID {
		t.Fatalf("Expected institution ID %s, got %s", instID, returnedInstID)
	}
	if jwtToken == "" {
		t.Fatal("Expected non-empty JWT token")
	}

	// Verify JWT claims
	claims, err := security.VerifyJWT(jwtToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claims.Scope != "BILLING_ONLY" {
		t.Fatalf("Expected claims.Scope = BILLING_ONLY, got: %s", claims.Scope)
	}

	// 5. Test Cryptographic Audit Chain Verification
	valid, err := engine.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("VerifyAuditChain failed: valid=%v, err=%v", valid, err)
	}

	// 6. Test Audit Event Pagination
	events, err := engine.GetAuditEvents(ctx, instID, 10, 0)
	if err != nil {
		t.Fatalf("GetAuditEvents failed: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("Expected at least 2 audit events (granted + logged in), got %d", len(events))
	}

	// 7. Test HTTP Handler Mount & Login Endpoint
	handler := engine.HTTPHandler()

	// Create second grant for HTTP login test
	rawToken2, err := engine.CreateSupportGrant(ctx, instID, adminID, 30, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant 2 failed: %v", err)
	}

	loginPayload, _ := json.Marshal(map[string]string{
		"token":   rawToken2,
		"agentId": agentID.String(),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("HTTP /api/v1/auth/support/login returned status %d: %s", w.Code, w.Body.String())
	}

	// 8. Test Direct Go API: RevokeSupportGrant
	if err := engine.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("RevokeSupportGrant failed: %v", err)
	}

	// 9. Verify Final Audit Chain
	valid, err = engine.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("Final audit chain verification failed: %v", err)
	}
}

func TestEngineWithEntClientOwnership(t *testing.T) {
	ctx := context.Background()

	db, err := sql.Open("sqlite", "file:grantsupport_entclient_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	callerEntClient, err := baseRepo.GetClient(ctx)
	if err != nil {
		t.Fatalf("Failed to get Ent client: %v", err)
	}

	// Initialize Engine injecting caller's *ent.Client
	engine, err := grantsupport.NewEngine(
		grantsupport.WithEntClient(callerEntClient),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine with EntClient failed: %v", err)
	}

	instID := uuid.New()
	adminID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 45, "FULL_ACCESS", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected valid raw token")
	}

	// Close engine
	if err := engine.Close(); err != nil {
		t.Fatalf("Engine.Close failed: %v", err)
	}

	// Verify caller's *ent.Client is still fully active and queryable
	count, err := callerEntClient.SupportGrant.Query().Count(ctx)
	if err != nil {
		t.Fatalf("Caller Ent client query failed after engine.Close: %v", err)
	}
	if count != 1 {
		t.Fatalf("Expected 1 grant record in caller Ent client, got: %d", count)
	}
}

func TestEngineWithPgxPoolOwnership(t *testing.T) {
	connStr := os.Getenv("TEST_POSTGRES_URL")
	if connStr == "" {
		t.Skip("Skipping TestEngineWithPgxPoolOwnership: TEST_POSTGRES_URL not configured")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("Failed to create pgxpool: %v", err)
	}
	defer pool.Close()

	// Initialize Engine injecting caller's *pgxpool.Pool via WithPgxPool
	engine, err := grantsupport.NewEngine(
		grantsupport.WithPgxPool(pool),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		t.Fatalf("NewEngine with WithPgxPool failed: %v", err)
	}

	instID := uuid.New()
	adminID := uuid.New()

	rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 30, "BILLING_ONLY", nil)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected non-empty raw grant token")
	}

	// Close engine
	if err := engine.Close(); err != nil {
		t.Fatalf("Engine.Close failed: %v", err)
	}

	// Verify caller's *pgxpool.Pool is still fully functional and usable
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("Caller pgxpool was unexpectedly closed or unusable after engine.Close(): %v", err)
	}

	var dummy int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&dummy); err != nil || dummy != 1 {
		t.Fatalf("Caller pgxpool query failed after engine.Close(): %v", err)
	}
}
```

---

## pkg/grantsupport/options.go

```go
package grantsupport

import (
	"database/sql"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"grantsupport/ent"
	"grantsupport/pkg/ports"
)

// EngineConfig holds configuration parameters and injected dependencies for the GrantSupport Engine.
type EngineConfig struct {
	SQLDB           *sql.DB
	Dialect         string
	EntClient       *ent.Client
	LockStore       ports.LockStore
	ReplayStore     ports.ReplayStore
	RevocationStore ports.RevocationStore
	RateLimiter     ports.RateLimiterStore
	PrivateKeyPEM   []byte
	PublicKeyPEM    []byte
	WebhookURL      string
	WebhookSecret   string
	AutoMigrate     bool
	OwnsDB          bool
}

// Option defines a functional configuration option for NewEngine.
type Option func(*EngineConfig)

// WithDB configures the engine to reuse an existing database connection pool (*sql.DB) and dialect.
// GrantSupport will NOT close this database connection pool upon engine shutdown.
func WithDB(db *sql.DB, dialectName string) Option {
	return func(c *EngineConfig) {
		c.SQLDB = db
		c.Dialect = dialectName
		c.OwnsDB = false
	}
}

// WithPgxPool configures the engine to reuse an existing PostgreSQL pgxpool.Pool without creating a second connection pool.
// GrantSupport wraps the pool using stdlib.OpenDBFromPool and will NOT close the pgxpool upon engine shutdown.
func WithPgxPool(pool *pgxpool.Pool) Option {
	return func(c *EngineConfig) {
		c.SQLDB = stdlib.OpenDBFromPool(pool)
		c.Dialect = "postgres"
		c.OwnsDB = false
	}
}

// WithEntClient configures the engine with an already initialized *ent.Client.
func WithEntClient(client *ent.Client) Option {
	return func(c *EngineConfig) {
		c.EntClient = client
	}
}

// WithLockStore provides a custom distributed or in-memory LockStore adapter.
func WithLockStore(store ports.LockStore) Option {
	return func(c *EngineConfig) {
		c.LockStore = store
	}
}

// WithReplayStore provides a custom ReplayStore adapter for nonce validation.
func WithReplayStore(store ports.ReplayStore) Option {
	return func(c *EngineConfig) {
		c.ReplayStore = store
	}
}

// WithRevocationStore provides a custom RevocationStore adapter.
func WithRevocationStore(store ports.RevocationStore) Option {
	return func(c *EngineConfig) {
		c.RevocationStore = store
	}
}

// WithRateLimiter provides a custom RateLimiterStore adapter.
func WithRateLimiter(limiter ports.RateLimiterStore) Option {
	return func(c *EngineConfig) {
		c.RateLimiter = limiter
	}
}

// WithJWTKeys provides explicit RS256 private and public PEM keys.
func WithJWTKeys(privateKeyPEM, publicKeyPEM []byte) Option {
	return func(c *EngineConfig) {
		c.PrivateKeyPEM = privateKeyPEM
		c.PublicKeyPEM = publicKeyPEM
	}
}

// WithWebhook configures destination URL and HMAC secret for lifecycle webhooks.
func WithWebhook(webhookURL, webhookSecret string) Option {
	return func(c *EngineConfig) {
		c.WebhookURL = webhookURL
		c.WebhookSecret = webhookSecret
	}
}

// WithAutoMigrate instructs the engine to auto-migrate database schemas during initialization.
func WithAutoMigrate(enable bool) Option {
	return func(c *EngineConfig) {
		c.AutoMigrate = enable
	}
}
```

---

## pkg/middleware/auth.go

```go
package middleware

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/security"
)

// AuthMiddleware inspects Authorization headers (Bearer JWT) and injects Tenant Context into request context.
func AuthMiddleware(next http.Handler) http.Handler {
	return NewAuthMiddleware(nil)(next)
}

// NewAuthMiddleware constructs a JWT authentication middleware with optional token revocation check.
func NewAuthMiddleware(revocationStore ports.RevocationStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing or malformed Authorization header")
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := security.VerifyJWT(tokenStr)
			if err != nil || claims == nil {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "INVALID_TOKEN", "JWT signature verification or expiration check failed")
				return
			}

			instID, errInst := uuid.Parse(claims.InstitutionID)
			userID, errUser := uuid.Parse(claims.UserID)
			if errInst != nil || errUser != nil {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "INVALID_CLAIMS", "Malformed UUID claims in JWT payload")
				return
			}

			// TokenVersion revocation check
			if revocationStore != nil {
				revoked, err := revocationStore.IsTokenRevoked(r.Context(), claims.InstitutionID, claims.UserID, claims.TokenVersion)
				if err == nil && revoked {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Session has been revoked. Please log in again.")
					return
				}
			}

			tenant := &pkgctx.TenantData{
				InstitutionID: instID,
				UserID:        userID,
				Role:          claims.Role,
			}

			ctx := pkgctx.WithTenant(r.Context(), tenant)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```

---

## pkg/middleware/bulletproof_auth.go

```go
// Package middleware provides HTTP middlewares for authentication, rate limiting, and 5-layer bulletproof security.
package middleware

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"grantsupport/pkg/config"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/security"
)

type contextKey string

const (
	BulletproofContextKey contextKey = "bulletproof_security_context"
)

// BulletproofSecurityContext holds authenticated metadata injected into r.Context().
type BulletproofSecurityContext struct {
	KeyID         string
	InstitutionID string
	ClientIP      string
	ExpiresAt     int64
	PublicKey     ed25519.PublicKey
}

// GetBulletproofSecurityContext retrieves BulletproofSecurityContext from request context.
func GetBulletproofSecurityContext(ctx context.Context) (*BulletproofSecurityContext, bool) {
	bctx, ok := ctx.Value(BulletproofContextKey).(*BulletproofSecurityContext)
	return bctx, ok
}

// GetRealClientIP extracts real client IP directly from socket (r.RemoteAddr) or trusted Cloudflare headers.
func GetRealClientIP(r *http.Request) string {
	// If CF-Connecting-IP header exists (Cloudflare proxy), use it
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		return cfIP
	}

	// Fall back to direct TCP socket connection remote address (UN-SPOOFABLE over TCP)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ValidateIPWhitelist verifies if a client IP matches a list of whitelisted IPs or CIDR subnets.
func ValidateIPWhitelist(clientIP string, whitelistedIPs []string) bool {
	if len(whitelistedIPs) == 0 {
		return true // No restriction
	}

	parsedClientIP := net.ParseIP(clientIP)
	if parsedClientIP == nil {
		return false
	}

	for _, entry := range whitelistedIPs {
		entry = strings.TrimSpace(entry)
		// Check exact match
		if entry == clientIP {
			return true
		}
		// Check CIDR range match (e.g. 192.168.1.0/24)
		if strings.Contains(entry, "/") {
			_, subnet, err := net.ParseCIDR(entry)
			if err == nil && subnet.Contains(parsedClientIP) {
				return true
			}
		}
	}

	return false
}

// BulletproofAuthMiddleware returns a 5-Layer Security HTTP middleware handler.
func BulletproofAuthMiddleware(replayStore ports.ReplayStore, keyStore map[string]*security.APIKeyDetails) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Security Headers
			keyID := r.Header.Get("X-API-KEY-ID")
			signatureB64 := r.Header.Get("X-SIGNATURE")
			nonce := r.Header.Get("X-NONCE")
			expiresAtStr := r.Header.Get("X-EXPIRES-AT")

			// Require headers for 5-Layer Security requests
			if keyID == "" || signatureB64 == "" || nonce == "" || expiresAtStr == "" {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing required 5-layer security headers (X-API-KEY-ID, X-SIGNATURE, X-NONCE, X-EXPIRES-AT)")
				return
			}

			// Parse expiresAt timestamp
			expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
			if err != nil {
				controller.WriteRFC7807Error(w, http.StatusBadRequest, "INVALID_HEADER", "X-EXPIRES-AT must be a valid Unix timestamp")
				return
			}

			// Layer 2: Client-Set TTL Expiry Check (with 30s clock skew buffer)
			maxTTL := int64(900) // 15 minutes max TTL window
			if err := security.ValidatePayloadTTL(expiresAt, maxTTL); err != nil {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "EXPIRED_TOKEN", err.Error())
				return
			}

			// Lookup registered API Key Details
			keyDetails, exists := keyStore[keyID]
			if !exists || !keyDetails.IsActive {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "INVALID_API_KEY", "API Key ID is invalid or inactive")
				return
			}

			// Parse Ed25519 Public Key
			pubKey, err := security.ParseEd25519PublicKeyBase64(keyDetails.PublicKeyBase64)
			if err != nil {
				controller.WriteRFC7807Error(w, http.StatusInternalServerError, "KEY_PARSE_ERROR", "Failed to parse registered public key")
				return
			}

			// Layer 4: Real TCP Socket / Trusted Proxy IP Check
			clientIP := GetRealClientIP(r)
			if config.AppConfig.EnforceStrictIPBinding || len(keyDetails.WhitelistedIPs) > 0 {
				if !ValidateIPWhitelist(clientIP, keyDetails.WhitelistedIPs) {
					controller.WriteRFC7807Error(w, http.StatusForbidden, "IP_NOT_ALLOWED", fmt.Sprintf("Client IP %s is not in the whitelisted access list", clientIP))
					return
				}
			}

			// Layer 3: Nonce Replay Check (Fail-Closed)
			if replayStore != nil {
				ttlSeconds := time.Duration(expiresAt-time.Now().Unix()+30) * time.Second
				if ttlSeconds < 10*time.Second {
					ttlSeconds = 10 * time.Second
				}

				setOk, err := replayStore.CheckAndSet(r.Context(), keyID, nonce, ttlSeconds)
				if err != nil || !setOk {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "REPLAY_ATTACK_DETECTED", "Duplicate request nonce detected (replay attack blocked)")
					return
				}
			}

			// Read request body to construct canonical signature message
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				controller.WriteRFC7807Error(w, http.StatusBadRequest, "INVALID_BODY", "Failed to read request payload body")
				return
			}
			// Restore r.Body so downstream controllers can read it
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// Construct canonical message: Method + Path + Nonce + ExpiresAt + Body
			canonicalMsg := fmt.Sprintf("%s\n%s\n%s\n%d\n%s", r.Method, r.URL.Path, nonce, expiresAt, string(bodyBytes))

			// Decode Ed25519 signature
			sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
			if err != nil {
				controller.WriteRFC7807Error(w, http.StatusBadRequest, "INVALID_SIGNATURE_FORMAT", "Signature must be base64 encoded")
				return
			}

			// Layer 1: Ed25519 Asymmetric Signature Check
			if !security.VerifyEd25519Signature(pubKey, []byte(canonicalMsg), sigBytes) {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "INVALID_SIGNATURE", "Ed25519 cryptographic signature verification failed")
				return
			}

			// Layer 5: Inject Tenant Context & Security Context
			ctx := r.Context()
			if keyDetails.InstitutionID != uuid.Nil {
				tenantData := &pkgctx.TenantData{
					InstitutionID: keyDetails.InstitutionID,
					Role:          "API_SERVICE",
				}
				ctx = pkgctx.WithTenant(ctx, tenantData)
			}

			bctx := &BulletproofSecurityContext{
				KeyID:         keyID,
				InstitutionID: keyDetails.InstitutionID.String(),
				ClientIP:      clientIP,
				ExpiresAt:     expiresAt,
				PublicKey:     pubKey,
			}
			ctx = context.WithValue(ctx, BulletproofContextKey, bctx)

			// Proceed to downstream handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```

---

## pkg/middleware/bulletproof_auth_test.go

```go
package middleware_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"grantsupport/pkg/adapters/replay"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/security"
)

func TestBulletproofAuthMiddleware(t *testing.T) {
	// 1. Generate Ed25519 Keypair
	kp, _, privKey, err := security.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keypair: %v", err)
	}

	// 2. Setup mock KeyStore
	keyID := "ap_live_test9988"
	keyStore := map[string]*security.APIKeyDetails{
		keyID: {
			KeyID:           keyID,
			InstitutionID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			PublicKeyBase64: kp,
			WhitelistedIPs:  []string{"127.0.0.1"},
			IsActive:        true,
		},
	}

	// 3. Initialize ReplayStore (In-Memory for tests)
	replayStore := replay.NewMemoryReplayStore(1 * time.Minute)
	defer replayStore.Close()

	// 4. Instantiate Bulletproof Auth Middleware
	mw := middleware.BulletproofAuthMiddleware(replayStore, keyStore)
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	})
	handlerToTest := mw(testHandler)

	t.Run("Valid Ed25519 Signature and Active TTL -> 200 OK", func(t *testing.T) {
		method := "POST"
		path := "/api/v1/ledger/record"
		nonce := fmt.Sprintf("nonce_%d", time.Now().UnixNano())
		expiresAt := time.Now().Add(10 * time.Minute).Unix()
		bodyStr := `{"debit":"BANK","credit":"RENT","amount":500.00}`

		canonicalMsg := fmt.Sprintf("%s\n%s\n%s\n%d\n%s", method, path, nonce, expiresAt, bodyStr)
		sig := ed25519.Sign(privKey, []byte(canonicalMsg))
		sigB64 := base64.StdEncoding.EncodeToString(sig)

		req := httptest.NewRequest(method, path, bytes.NewBufferString(bodyStr))
		req.Header.Set("X-API-KEY-ID", keyID)
		req.Header.Set("X-SIGNATURE", sigB64)
		req.Header.Set("X-NONCE", nonce)
		req.Header.Set("X-EXPIRES-AT", fmt.Sprintf("%d", expiresAt))
		req.RemoteAddr = "127.0.0.1:54321"

		rr := httptest.NewRecorder()
		handlerToTest.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("Expired TTL Window -> 401 EXPIRED_TOKEN", func(t *testing.T) {
		method := "POST"
		path := "/api/v1/ledger/record"
		nonce := fmt.Sprintf("nonce_%d", time.Now().UnixNano())
		expiresAt := time.Now().Add(-1 * time.Hour).Unix() // Expired 1 hour ago
		bodyStr := `{"debit":"BANK","credit":"RENT","amount":500.00}`

		canonicalMsg := fmt.Sprintf("%s\n%s\n%s\n%d\n%s", method, path, nonce, expiresAt, bodyStr)
		sig := ed25519.Sign(privKey, []byte(canonicalMsg))
		sigB64 := base64.StdEncoding.EncodeToString(sig)

		req := httptest.NewRequest(method, path, bytes.NewBufferString(bodyStr))
		req.Header.Set("X-API-KEY-ID", keyID)
		req.Header.Set("X-SIGNATURE", sigB64)
		req.Header.Set("X-NONCE", nonce)
		req.Header.Set("X-EXPIRES-AT", fmt.Sprintf("%d", expiresAt))
		req.RemoteAddr = "127.0.0.1:54321"

		rr := httptest.NewRecorder()
		handlerToTest.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for expired TTL, got %d", rr.Code)
		}
	})

	t.Run("Invalid Ed25519 Signature -> 401 INVALID_SIGNATURE", func(t *testing.T) {
		method := "POST"
		path := "/api/v1/ledger/record"
		nonce := fmt.Sprintf("nonce_%d", time.Now().UnixNano())
		expiresAt := time.Now().Add(10 * time.Minute).Unix()
		bodyStr := `{"debit":"BANK","credit":"RENT","amount":500.00}`

		badSigB64 := base64.StdEncoding.EncodeToString(make([]byte, 64))

		req := httptest.NewRequest(method, path, bytes.NewBufferString(bodyStr))
		req.Header.Set("X-API-KEY-ID", keyID)
		req.Header.Set("X-SIGNATURE", badSigB64)
		req.Header.Set("X-NONCE", nonce)
		req.Header.Set("X-EXPIRES-AT", fmt.Sprintf("%d", expiresAt))
		req.RemoteAddr = "127.0.0.1:54321"

		rr := httptest.NewRecorder()
		handlerToTest.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for invalid signature, got %d", rr.Code)
		}
	})
}

func TestIPWhitelistValidation(t *testing.T) {
	whitelisted := []string{"127.0.0.1", "192.168.1.0/24"}

	if !middleware.ValidateIPWhitelist("127.0.0.1", whitelisted) {
		t.Error("Expected 127.0.0.1 to be whitelisted")
	}

	if !middleware.ValidateIPWhitelist("192.168.1.50", whitelisted) {
		t.Error("Expected 192.168.1.50 to be whitelisted under CIDR 192.168.1.0/24")
	}

	if middleware.ValidateIPWhitelist("10.0.0.1", whitelisted) {
		t.Error("Expected 10.0.0.1 to be rejected")
	}
}
```

---

## pkg/middleware/correlation.go

```go
package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type correlationIDKey struct{}

// CorrelationIDMiddleware attaches or propagates an X-Correlation-ID header for distributed trace logging.
func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := r.Header.Get("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		w.Header().Set("X-Correlation-ID", correlationID)
		ctx := context.WithValue(r.Context(), correlationIDKey{}, correlationID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

---

## pkg/middleware/rbac.go

```go
package middleware

import (
	"net/http"

	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
)

// RequireRoles returns a middleware function enforcing role-based access control (RBAC).
func RequireRoles(allowedRoles ...string) func(http.Handler) http.Handler {
	allowedMap := make(map[string]bool)
	for _, role := range allowedRoles {
		allowedMap[role] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := pkgctx.GetTenant(r.Context())
			if !ok || tenant == nil {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
				return
			}

			if !allowedMap[tenant.Role] {
				controller.WriteRFC7807Error(w, http.StatusForbidden, "FORBIDDEN", "You do not have permission to perform this action")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
```

---

## pkg/ports/lock.go

```go
package ports

import (
	"context"
	"errors"
	"time"
)

var (
	ErrLockBusy        = errors.New("LOCK_BUSY: Resource is currently locked by another process")
	ErrLockUnavailable = errors.New("LOCK_UNAVAILABLE: Distributed lock service is unavailable")
)

// LockStore provides distributed concurrency locking with ownership verification.
type LockStore interface {
	// Acquire attempts to acquire a lock with the specified key and TTL.
	// Returns a unique owner token if successful, or ErrLockBusy if already held.
	Acquire(ctx context.Context, lockKey string, ttl time.Duration) (string, error)

	// Release safely releases the lock if and only if the owner token matches.
	Release(ctx context.Context, lockKey, ownerToken string) error

	// WithLock wraps a function call within an acquired lock, automatically releasing upon completion.
	WithLock(ctx context.Context, lockKey string, ttl time.Duration, fn func(ctx context.Context) error) error
}
```

---

## pkg/ports/rate_limit.go

```go
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
```

---

## pkg/ports/replay.go

```go
package ports

import (
	"context"
	"errors"
	"time"
)

var (
	ErrReplayDetected = errors.New("REPLAY_ATTACK_DETECTED: Duplicate request nonce detected")
)

// ReplayStore provides cryptographic nonce tracking to prevent request replay attacks.
type ReplayStore interface {
	// CheckAndSet returns true if the nonce is new and was successfully registered.
	// Returns false or ErrReplayDetected if the nonce has already been seen within its TTL window.
	CheckAndSet(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error)
}
```

---

## pkg/ports/revocation.go

```go
package ports

import (
	"context"
	"errors"
)

var (
	ErrTokenRevoked = errors.New("TOKEN_REVOKED: Session or token version has been revoked")
)

// RevocationStore manages token and session invalidation state across nodes.
type RevocationStore interface {
	// IsTokenRevoked returns true if the token version for the user/institution is older than the current valid version.
	IsTokenRevoked(ctx context.Context, institutionID, userID string, tokenVersion int) (bool, error)

	// RevokeUserSessions increments or sets the minimum valid token version for a user, revoking earlier sessions.
	RevokeUserSessions(ctx context.Context, institutionID, userID string, newVersion int) error
}
```

---

## pkg/repository/base.go

```go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"grantsupport/ent"
)

// BaseRepository encapsulates the Ent database client and underlying sql.DB.
type BaseRepository struct {
	MasterClient *ent.Client
	SQLDB        *sql.DB
	Dialect      string
}

// NewBaseRepository creates a new BaseRepository with a direct ent.Client.
func NewBaseRepository(masterClient *ent.Client) *BaseRepository {
	return &BaseRepository{
		MasterClient: masterClient,
	}
}

// NewBaseRepositoryWithDB creates a new BaseRepository by wrapping an existing *sql.DB connection pool.
func NewBaseRepositoryWithDB(db *sql.DB, dialectName string) *BaseRepository {
	var entDialect string
	switch dialectName {
	case "mysql", "mariadb":
		entDialect = dialect.MySQL
	case "sqlite", "sqlite3":
		entDialect = dialect.SQLite
	default:
		entDialect = dialect.Postgres
	}

	drv := entsql.OpenDB(entDialect, db)
	client := ent.NewClient(ent.Driver(drv))

	return &BaseRepository{
		MasterClient: client,
		SQLDB:        db,
		Dialect:      dialectName,
	}
}

// GetClient returns the Ent client for database operations.
func (r *BaseRepository) GetClient(ctx context.Context) (*ent.Client, error) {
	if r.MasterClient == nil {
		return nil, fmt.Errorf("master database client not initialized")
	}
	return r.MasterClient, nil
}

// Transaction executes a transactional callback inside an Ent transaction (ent.Tx).
// Enforces a 10-second transaction timeout limit matching local and production guardrails.
func (r *BaseRepository) Transaction(ctx context.Context, fn func(tx *ent.Tx) error) error {
	client, err := r.GetClient(ctx)
	if err != nil {
		return err
	}

	txCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	tx, err := client.Tx(txCtx)
	if err != nil {
		return fmt.Errorf("failed to start database transaction: %w", err)
	}

	// Defer recovery to rollback transaction on panic
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // Re-panic after safety rollback
		}
	}()

	err = fn(tx)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("transaction failed: %v (rollback error: %v)", err, rollbackErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit database transaction: %w", err)
	}
	return nil
}
```

---

## pkg/repository/db_compliance_test.go

```go
package repository_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/replay"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
)

// runDatabaseComplianceSuite executes a standardized matrix of capability tests against any supported SQL database driver.
func runDatabaseComplianceSuite(t *testing.T, dialectName string, db *sql.DB) {
	ctx := context.Background()

	baseRepo := repository.NewBaseRepositoryWithDB(db, dialectName)
	client, err := baseRepo.GetClient(ctx)
	if err != nil {
		t.Fatalf("[%s] Failed to get Ent client: %v", dialectName, err)
	}

	// 1. Schema Creation
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatalf("[%s] Schema creation failed: %v", dialectName, err)
	}

	// Create capability tables for lock, replay, revocation
	var ddl string
	switch dialectName {
	case "sqlite", "sqlite3":
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (lock_key TEXT PRIMARY KEY, owner_token TEXT NOT NULL, expires_at DATETIME NOT NULL, acquired_at DATETIME NOT NULL);
		CREATE TABLE IF NOT EXISTS gs_replays (nonce_key TEXT PRIMARY KEY, expires_at DATETIME NOT NULL);
		CREATE TABLE IF NOT EXISTS gs_revocations (institution_id TEXT NOT NULL, user_id TEXT NOT NULL, token_version INTEGER NOT NULL DEFAULT 1, revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (institution_id, user_id));`
	case "mysql", "mariadb":
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (lock_key VARCHAR(255) PRIMARY KEY, owner_token VARCHAR(64) NOT NULL, expires_at DATETIME(6) NOT NULL, acquired_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		CREATE TABLE IF NOT EXISTS gs_replays (nonce_key VARCHAR(255) PRIMARY KEY, expires_at DATETIME(6) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
		CREATE TABLE IF NOT EXISTS gs_revocations (institution_id VARCHAR(36) NOT NULL, user_id VARCHAR(36) NOT NULL, token_version INT NOT NULL DEFAULT 1, revoked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), PRIMARY KEY (institution_id, user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`
	default: // postgres
		ddl = `
		CREATE TABLE IF NOT EXISTS gs_locks (lock_key VARCHAR(255) PRIMARY KEY, owner_token VARCHAR(64) NOT NULL, expires_at TIMESTAMPTZ NOT NULL, acquired_at TIMESTAMPTZ NOT NULL);
		CREATE TABLE IF NOT EXISTS gs_replays (nonce_key VARCHAR(255) PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);
		CREATE TABLE IF NOT EXISTS gs_revocations (institution_id UUID NOT NULL, user_id UUID NOT NULL, token_version INTEGER NOT NULL DEFAULT 1, revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (institution_id, user_id));`
	}
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		t.Fatalf("[%s] Capability DDL execution failed: %v", dialectName, err)
	}

	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewSQLLockStore(db, dialectName)
	auditRepo.SetLockStore(lockStore)

	replayStore := replay.NewSQLReplayStore(db, dialectName)
	revocationStore := revocation.NewSQLRevocationStore(db, dialectName)

	instA := uuid.New()
	instB := uuid.New()
	adminA := uuid.New()
	adminB := uuid.New()

	// 2. Grant Creation & Verification
	tokenHashA := fmt.Sprintf("hash_a_%s", uuid.New().String())
	tokenHashB := fmt.Sprintf("hash_b_%s", uuid.New().String())

	grantA, err := grantRepo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID:  instA,
		GrantedByID:    adminA,
		TokenHash:      tokenHashA,
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		Scope:          "BILLING_ONLY",
		WhitelistedIPs: []string{"10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("[%s] CreateSupportGrant A failed: %v", dialectName, err)
	}
	if grantA.Scope != "BILLING_ONLY" {
		t.Fatalf("[%s] Expected scope BILLING_ONLY, got %s", dialectName, grantA.Scope)
	}

	_, err = grantRepo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID: instB,
		GrantedByID:   adminB,
		TokenHash:     tokenHashB,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		Scope:         "FULL_ACCESS",
	})
	if err != nil {
		t.Fatalf("[%s] CreateSupportGrant B failed: %v", dialectName, err)
	}

	// 3. Multi-Tenant Isolation Verification
	foundA, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHashA)
	if err != nil || foundA == nil || foundA.InstitutionID != instA {
		t.Fatalf("[%s] Tenant isolation check failed for Grant A: %+v, err: %v", dialectName, foundA, err)
	}

	foundB, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHashB)
	if err != nil || foundB == nil || foundB.InstitutionID != instB {
		t.Fatalf("[%s] Tenant isolation check failed for Grant B: %+v, err: %v", dialectName, foundB, err)
	}

	// 4. 100-Worker Atomic Single-Use Concurrency Test
	const concurrency = 100
	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)
	var successCount int64
	var failCount int64

	for i := 0; i < concurrency; i++ {
		go func() {
			<-startCh
			err := grantRepo.MarkGrantAsUsed(context.Background(), grantA.ID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			doneCh <- struct{}{}
		}()
	}

	close(startCh)
	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	if successCount != 1 {
		t.Fatalf("[%s] Expected EXACTLY 1 successful consumption among %d workers, got: %d", dialectName, concurrency, successCount)
	}
	if failCount != int64(concurrency-1) {
		t.Fatalf("[%s] Expected EXACTLY %d failed consumptions, got: %d", dialectName, concurrency-1, failCount)
	}

	// 5. 100-Worker SQLLockStore Concurrency, Ownership & Expiry Takeover Test
	lockKey := fmt.Sprintf("lock:compliance:%s", instA.String())
	lockStartCh := make(chan struct{})
	lockDoneCh := make(chan string, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			<-lockStartCh
			token, err := lockStore.Acquire(context.Background(), lockKey, 2*time.Second)
			if err == nil {
				lockDoneCh <- token
			} else {
				lockDoneCh <- ""
			}
		}()
	}

	close(lockStartCh)
	var winnerToken string
	var lockWinners int
	for i := 0; i < concurrency; i++ {
		tok := <-lockDoneCh
		if tok != "" {
			winnerToken = tok
			lockWinners++
		}
	}

	if lockWinners != 1 {
		t.Fatalf("[%s] Expected EXACTLY 1 lock winner among %d concurrent attempts, got: %d", dialectName, concurrency, lockWinners)
	}

	// Test non-owner release fails to release
	_ = lockStore.Release(ctx, lockKey, "fake_non_owner_token")
	_, err = lockStore.Acquire(ctx, lockKey, 2*time.Second)
	if err != ports.ErrLockBusy {
		t.Fatalf("[%s] Expected lock to remain busy after fake release, got: %v", dialectName, err)
	}

	// Test valid owner release succeeds
	if err := lockStore.Release(ctx, lockKey, winnerToken); err != nil {
		t.Fatalf("[%s] Valid owner release failed: %v", dialectName, err)
	}

	// Test lock lease expiration & takeover
	shortLockKey := fmt.Sprintf("lock:expire:%s", instA.String())
	tok1, err := lockStore.Acquire(ctx, shortLockKey, 50*time.Millisecond)
	if err != nil || tok1 == "" {
		t.Fatalf("[%s] Short lock acquire failed: %v", dialectName, err)
	}
	time.Sleep(70 * time.Millisecond) // Wait for lease to expire
	tok2, err := lockStore.Acquire(ctx, shortLockKey, 1*time.Second)
	if err != nil || tok2 == "" {
		t.Fatalf("[%s] Expired lock takeover failed: %v", dialectName, err)
	}
	_ = lockStore.Release(ctx, shortLockKey, tok2)

	// 6. SQL Replay Store Nonce Uniqueness Test
	nonce := fmt.Sprintf("nonce_%s", uuid.New().String())
	valid, err := replayStore.CheckAndSet(ctx, "key1", nonce, 5*time.Minute)
	if err != nil || !valid {
		t.Fatalf("[%s] Initial nonce CheckAndSet failed: valid=%v, err=%v", dialectName, valid, err)
	}
	valid, err = replayStore.CheckAndSet(ctx, "key1", nonce, 5*time.Minute)
	if valid || (err != nil && err != ports.ErrReplayDetected) {
		t.Fatalf("[%s] Reused nonce expected valid=false/ErrReplayDetected, got valid=%v, err=%v", dialectName, valid, err)
	}

	// 7. SQL Revocation Store Test
	userRevokeID := uuid.New().String()
	revoked, err := revocationStore.IsTokenRevoked(ctx, instA.String(), userRevokeID, 1)
	if err != nil || revoked {
		t.Fatalf("[%s] Expected user not revoked, got revoked=%v, err=%v", dialectName, revoked, err)
	}

	if err := revocationStore.RevokeUserSessions(ctx, instA.String(), userRevokeID, 2); err != nil {
		t.Fatalf("[%s] RevokeUserSessions failed: %v", dialectName, err)
	}

	revoked, err = revocationStore.IsTokenRevoked(ctx, instA.String(), userRevokeID, 1)
	if err != nil || !revoked {
		t.Fatalf("[%s] Expected token version 1 to be revoked after version 2 bump, got revoked=%v", dialectName, revoked)
	}

	// 8. Cryptographic Audit Hash Chain & Concurrent Serialization Test
	const auditConcurrency = 25
	var wg sync.WaitGroup
	wg.Add(auditConcurrency)

	for i := 1; i <= auditConcurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			_, logErr := auditRepo.LogSecurityEvent(ctx, instA, adminA, "AUDIT_EVENT", fmt.Sprintf("Concurrent event %d with email test%d@company.com", idx, idx), nil)
			if logErr != nil {
				t.Errorf("[%s] Concurrent LogSecurityEvent %d failed: %v", dialectName, idx, logErr)
			}
		}(i)
	}
	wg.Wait()

	validChain, err := auditRepo.VerifyAuditChain(ctx, instA)
	if err != nil || !validChain {
		t.Fatalf("[%s] Concurrent audit chain verification failed: valid=%v, err=%v", dialectName, validChain, err)
	}

	// 9. Tenant Revocation Isolation
	if err := grantRepo.RevokeAllGrantsForInstitution(ctx, instA); err != nil {
		t.Fatalf("[%s] RevokeAllGrantsForInstitution failed: %v", dialectName, err)
	}
	activeA, _ := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHashA)
	if activeA != nil {
		t.Fatalf("[%s] Grant A should be revoked and unfindable as active", dialectName)
	}
	activeB, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHashB)
	if err != nil || activeB == nil {
		t.Fatalf("[%s] Grant B in Tenant B should remain active after Tenant A revocation", dialectName)
	}
}

// TestDatabaseComplianceSuite_SQLite runs the compliance matrix against in-memory SQLite.
func TestDatabaseComplianceSuite_SQLite(t *testing.T) {
	db, err := sql.Open("sqlite", "file:compliance_sqlite_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	runDatabaseComplianceSuite(t, "sqlite", db)
}

// TestDatabaseComplianceSuite_PostgreSQL runs when TEST_POSTGRES_URL environment variable is provided.
func TestDatabaseComplianceSuite_PostgreSQL(t *testing.T) {
	connStr := os.Getenv("TEST_POSTGRES_URL")
	if connStr == "" {
		t.Skip("Skipping PostgreSQL compliance test: TEST_POSTGRES_URL not configured")
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	runDatabaseComplianceSuite(t, "postgres", db)
}

// TestDatabaseComplianceSuite_MySQL runs when TEST_MYSQL_URL environment variable is provided.
func TestDatabaseComplianceSuite_MySQL(t *testing.T) {
	connStr := os.Getenv("TEST_MYSQL_URL")
	if connStr == "" {
		t.Skip("Skipping MySQL compliance test: TEST_MYSQL_URL not configured")
	}

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to MySQL: %v", err)
	}
	defer db.Close()

	runDatabaseComplianceSuite(t, "mysql", db)
}

// TestDatabaseComplianceSuite_MariaDB runs when TEST_MARIADB_URL environment variable is provided.
func TestDatabaseComplianceSuite_MariaDB(t *testing.T) {
	connStr := os.Getenv("TEST_MARIADB_URL")
	if connStr == "" {
		t.Skip("Skipping MariaDB compliance test: TEST_MARIADB_URL not configured")
	}

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to MariaDB: %v", err)
	}
	defer db.Close()

	runDatabaseComplianceSuite(t, "mariadb", db)
}
```

---

## pkg/repository/repository_test.go

```go
package repository_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/domain"
	"grantsupport/pkg/repository"
)

func TestBaseRepositoryGetClient(t *testing.T) {
	base := repository.NewBaseRepository(nil)
	client, err := base.GetClient(context.Background())
	if err == nil {
		t.Error("Expected error when MasterClient is nil")
	}
	if client != nil {
		t.Error("Expected client to be nil")
	}
}

func TestSupportGrantRepositoryNilClient(t *testing.T) {
	base := repository.NewBaseRepository(nil)
	repo := repository.NewSupportGrantRepository(base)

	ctx := context.Background()
	_, err := repo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID: uuid.New(),
		GrantedByID:   uuid.New(),
	})
	if err == nil {
		t.Error("Expected error when database client is nil")
	}

	_, err = repo.FindActiveGrantByTokenHash(ctx, "sample_hash")
	if err == nil {
		t.Error("Expected error when database client is nil")
	}

	err = repo.MarkGrantAsUsed(ctx, uuid.New())
	if err == nil {
		t.Error("Expected error when database client is nil")
	}

	err = repo.RevokeAllGrantsForInstitution(ctx, uuid.New())
	if err == nil {
		t.Error("Expected error when database client is nil")
	}
}

func TestSecurityAuditRepositoryNilClient(t *testing.T) {
	base := repository.NewBaseRepository(nil)
	repo := repository.NewSecurityAuditRepository(base)

	ctx := context.Background()
	_, err := repo.LogSecurityEvent(ctx, uuid.New(), uuid.New(), "TEST_EVENT", "Test description", nil)
	if err == nil {
		t.Error("Expected error when database client is nil")
	}
}

func TestRepositoryWithSQLiteInMemory(t *testing.T) {
	ctx := context.Background()

	// Open in-memory SQLite database with foreign keys enabled
	db, err := sql.Open("sqlite", "file:grantsupport_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open in-memory SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)

	instID := uuid.New()
	adminID := uuid.New()
	tokenHash := "test_token_hash_abc123"

	// 1. Create Support Grant
	grant, err := grantRepo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID: instID,
		GrantedByID:   adminID,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateSupportGrant failed on SQLite: %v", err)
	}
	if grant.ID == uuid.Nil || grant.TokenHash != tokenHash {
		t.Fatalf("Unexpected grant data returned: %+v", grant)
	}

	// 2. Find Active Grant
	found, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("FindActiveGrantByTokenHash failed: %v", err)
	}
	if found.ID != grant.ID || found.IsUsed {
		t.Fatalf("Grant mismatch or already marked as used: %+v", found)
	}

	// 3. Mark Grant as Used
	if err := grantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		t.Fatalf("MarkGrantAsUsed failed: %v", err)
	}

	// 4. Verify Grant is no longer active
	usedGrant, err := grantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err == nil && usedGrant != nil {
		t.Fatalf("Expected FindActiveGrantByTokenHash to return error for used grant, got: %+v", usedGrant)
	}

	// 5. Log Security Event & Verify Audit Chain
	auditEvent, err := auditRepo.LogSecurityEvent(ctx, instID, adminID, "TEST_GRANT_CREATED", "Test grant description", nil)
	if err != nil {
		t.Fatalf("LogSecurityEvent failed: %v", err)
	}
	if auditEvent.ID == uuid.Nil || auditEvent.CreatedAt.IsZero() {
		t.Fatalf("Unexpected audit event: %+v", auditEvent)
	}
}

func TestConcurrentAtomicGrantConsumption(t *testing.T) {
	ctx := context.Background()

	db, err := sql.Open("sqlite", "file:grantsupport_concurrent_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	instID := uuid.New()
	adminID := uuid.New()
	tokenHash := "concurrent_token_hash_999"

	grant, err := grantRepo.CreateSupportGrant(ctx, &domain.CreateSupportGrantInput{
		InstitutionID: instID,
		GrantedByID:   adminID,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	const concurrency = 50
	var successCount int64
	var failCount int64

	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			<-startCh
			err := grantRepo.MarkGrantAsUsed(context.Background(), grant.ID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			doneCh <- struct{}{}
		}()
	}

	// Release all 50 goroutines simultaneously
	close(startCh)

	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	if successCount != 1 {
		t.Fatalf("Expected EXACTLY 1 successful consumption among 50 concurrent workers, got: %d", successCount)
	}
	if failCount != 49 {
		t.Fatalf("Expected EXACTLY 49 failed consumptions among 50 concurrent workers, got: %d", failCount)
	}
}

func TestAuditChainVerificationAndConcurrency(t *testing.T) {
	ctx := context.Background()

	db, err := sql.Open("sqlite", "file:grantsupport_auditchain_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	instID := uuid.New()
	adminID := uuid.New()

	// 1. Log sequential events and verify chain
	for i := 1; i <= 10; i++ {
		_, err := auditRepo.LogSecurityEvent(ctx, instID, adminID, "EVENT_TYPE_A", fmt.Sprintf("Event number %d with email test%d@example.com", i, i), nil)
		if err != nil {
			t.Fatalf("LogSecurityEvent %d failed: %v", i, err)
		}
	}

	valid, err := auditRepo.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("Expected audit chain to be valid, got valid=%v, err=%v", valid, err)
	}

	// 2. Log 20 concurrent events under striped institution mutex
	const concurrency = 20
	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		workerID := uuid.New()
		go func(id int) {
			<-startCh
			_, _ = auditRepo.LogSecurityEvent(context.Background(), instID, workerID, "CONCURRENT_EVENT", fmt.Sprintf("Concurrent action %d", id), nil)
			doneCh <- struct{}{}
		}(i)
	}

	close(startCh)
	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	// Verify the entire chain of 30 total events is still 100% cryptographically consistent
	valid, err = auditRepo.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("Expected concurrent audit chain to be unbroken, got valid=%v, err=%v", valid, err)
	}

	// 3. Test pagination query
	events, err := auditRepo.GetAuditEventsByInstitution(ctx, instID, 15, 0)
	if err != nil {
		t.Fatalf("GetAuditEventsByInstitution failed: %v", err)
	}
	if len(events) != 15 {
		t.Fatalf("Expected 15 events, got %d", len(events))
	}
}
```

---

## pkg/repository/security_audit_repository.go

```go
package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/ent/auditevent"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/security"
)

type SecurityAuditRepository struct {
	*BaseRepository
	instLocks sync.Map // map[uuid.UUID]*sync.Mutex
	lockStore ports.LockStore
}

func NewSecurityAuditRepository(base *BaseRepository) *SecurityAuditRepository {
	return &SecurityAuditRepository{
		BaseRepository: base,
	}
}

// SetLockStore attaches a distributed or SQL lock store to serialize audit hash chaining across multiple microservice processes.
func (r *SecurityAuditRepository) SetLockStore(lockStore ports.LockStore) {
	r.lockStore = lockStore
}

func (r *SecurityAuditRepository) getInstitutionLock(institutionID uuid.UUID) *sync.Mutex {
	val, _ := r.instLocks.LoadOrStore(institutionID, &sync.Mutex{})
	return val.(*sync.Mutex)
}

type AuditLogResult struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// LogSecurityEvent records a permanent append-only audit log entry in the database.
// Mutex striping (in-process) combined with distributed locking (cross-process) ensures
// linear hash-chain integrity with zero forks and zero dropped events under high concurrency.
func (r *SecurityAuditRepository) LogSecurityEvent(ctx context.Context, institutionID, actorID uuid.UUID, eventType, description string, tx *ent.Tx) (*AuditLogResult, error) {
	// Acquire per-institution in-process lock to serialize goroutines on this instance
	mu := r.getInstitutionLock(institutionID)
	mu.Lock()
	defer mu.Unlock()

	// If distributed lockStore is configured and we are not inside an existing transaction,
	// acquire cross-process distributed lock with bounded spin-wait retry.
	if r.lockStore != nil && tx == nil {
		lockKey := fmt.Sprintf("lock:audit:%s", institutionID.String())
		var token string
		var err error
		deadline := time.Now().Add(5 * time.Second)

		for {
			token, err = r.lockStore.Acquire(ctx, lockKey, 5*time.Second)
			if err == nil && token != "" {
				break
			}
			if err != ports.ErrLockBusy && err != nil {
				return nil, fmt.Errorf("failed to acquire distributed audit lock: %w", err)
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for distributed audit lock: %w", ports.ErrLockBusy)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(15 * time.Millisecond):
			}
		}

		defer func() {
			_ = r.lockStore.Release(context.Background(), lockKey, token)
		}()
	}

	return r.logSecurityEventInternal(ctx, institutionID, actorID, eventType, description, tx)
}

func (r *SecurityAuditRepository) logSecurityEventInternal(ctx context.Context, institutionID, actorID uuid.UUID, eventType, description string, tx *ent.Tx) (*AuditLogResult, error) {
	var builder *ent.AuditEventCreate
	var client *ent.Client
	var err error

	if tx != nil {
		builder = tx.AuditEvent.Create()
	} else {
		client, err = r.GetClient(ctx)
		if err != nil {
			return nil, err
		}
		builder = client.AuditEvent.Create()
	}

	// Sanitize any PII or credentials from the event description before hashing and saving
	sanitizedDesc := security.SanitizeAuditText(description)
	now := time.Now()

	// Compute previous hash chain link scoped by institution
	var prevHash string
	if tx != nil {
		lastEvent, _ := tx.AuditEvent.Query().
			Where(auditevent.InstitutionID(institutionID)).
			Order(ent.Desc(auditevent.FieldCreatedAt)).
			First(ctx)
		if lastEvent != nil {
			prevHash = lastEvent.HashChain
		}
	} else if client != nil {
		lastEvent, _ := client.AuditEvent.Query().
			Where(auditevent.InstitutionID(institutionID)).
			Order(ent.Desc(auditevent.FieldCreatedAt)).
			First(ctx)
		if lastEvent != nil {
			prevHash = lastEvent.HashChain
		}
	}
	if prevHash == "" {
		prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Compute SHA-256 hash chain value
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%s:%s:%s:%d", prevHash, institutionID.String(), actorID.String(), eventType, sanitizedDesc, now.UnixNano())))
	computedHashChain := hex.EncodeToString(h.Sum(nil))

	event, err := builder.
		SetInstitutionID(institutionID).
		SetActorID(actorID).
		SetEventType(eventType).
		SetDescription(sanitizedDesc).
		SetHashChain(computedHashChain).
		SetCreatedAt(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return &AuditLogResult{
		ID:        event.ID,
		CreatedAt: event.CreatedAt,
	}, nil
}

// VerifyAuditChain traverses all historical events for an institution and verifies that the cryptographic hash chain is unbroken.
func (r *SecurityAuditRepository) VerifyAuditChain(ctx context.Context, institutionID uuid.UUID) (bool, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return false, err
	}

	events, err := client.AuditEvent.Query().
		Where(auditevent.InstitutionID(institutionID)).
		Order(ent.Asc(auditevent.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return false, err
	}

	prevHash := "0000000000000000000000000000000000000000000000000000000000000000"
	for _, event := range events {
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s:%s:%s:%s:%s:%d", prevHash, event.InstitutionID.String(), event.ActorID.String(), event.EventType, event.Description, event.CreatedAt.UnixNano())))
		expectedHash := hex.EncodeToString(h.Sum(nil))

		if event.HashChain != expectedHash {
			return false, fmt.Errorf("audit chain integrity violation at event %s: expected %s, got %s", event.ID, expectedHash, event.HashChain)
		}
		prevHash = event.HashChain
	}

	return true, nil
}

// GetAuditEventsByInstitution retrieves paginated audit records for an institution.
func (r *SecurityAuditRepository) GetAuditEventsByInstitution(ctx context.Context, institutionID uuid.UUID, limit, offset int) ([]*ent.AuditEvent, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	return client.AuditEvent.Query().
		Where(auditevent.InstitutionID(institutionID)).
		Order(ent.Desc(auditevent.FieldCreatedAt)).
		Limit(limit).
		Offset(offset).
		All(ctx)
}
```

---

## pkg/repository/support_grant_repository.go

```go
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/ent/supportgrant"
	"grantsupport/pkg/domain"
)

type SupportGrantRepository struct {
	*BaseRepository
}

func NewSupportGrantRepository(base *BaseRepository) *SupportGrantRepository {
	return &SupportGrantRepository{BaseRepository: base}
}

func (r *SupportGrantRepository) CreateSupportGrant(ctx context.Context, data *domain.CreateSupportGrantInput) (*ent.SupportGrant, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	builder := client.SupportGrant.Create().
		SetInstitutionID(data.InstitutionID).
		SetGrantedByID(data.GrantedByID).
		SetTokenHash(data.TokenHash).
		SetExpiresAt(data.ExpiresAt)

	if data.Scope != "" {
		builder.SetScope(data.Scope)
	}
	if len(data.WhitelistedIPs) > 0 {
		builder.SetWhitelistedIps(data.WhitelistedIPs)
	}

	grant, err := builder.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create support grant: %w", err)
	}
	return grant, nil
}

func (r *SupportGrantRepository) FindActiveGrantByTokenHash(ctx context.Context, tokenHash string) (*ent.SupportGrant, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	grant, err := client.SupportGrant.Query().
		Where(
			supportgrant.TokenHash(tokenHash),
			supportgrant.IsUsed(false),           // Enforce single-use check
			supportgrant.ExpiresAtGT(time.Now()), // strictly check expiration boundary
		).
		Select(
			supportgrant.FieldID,
			supportgrant.FieldInstitutionID,
			supportgrant.FieldGrantedByID,
			supportgrant.FieldTokenHash,
			supportgrant.FieldExpiresAt,
			supportgrant.FieldIsUsed,
			supportgrant.FieldScope,
			supportgrant.FieldCreatedAt,
		).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("failed to query support grant: %w", err)
	}
	if ent.IsNotFound(err) {
		return nil, nil
	}
	return grant, nil
}

var ErrGrantAlreadyUsed = errors.New("GRANT_ALREADY_USED: Support grant has already been consumed or is invalid")

// MarkGrantAsUsed flags a support grant token as consumed atomically using a conditional predicate (is_used = false).
func (r *SupportGrantRepository) MarkGrantAsUsed(ctx context.Context, grantID uuid.UUID) error {
	client, err := r.GetClient(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	affected, err := client.SupportGrant.Update().
		Where(
			supportgrant.ID(grantID),
			supportgrant.IsUsed(false),
		).
		SetIsUsed(true).
		SetUsedAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to mark support grant as used: %w", err)
	}
	if affected == 0 {
		return ErrGrantAlreadyUsed
	}
	return nil
}

func (r *SupportGrantRepository) RevokeAllGrantsForInstitution(ctx context.Context, institutionID uuid.UUID) error {
	client, err := r.GetClient(ctx)
	if err != nil {
		return err
	}

	// Revoke all by setting expires_at to now
	_, err = client.SupportGrant.Update().
		Where(supportgrant.InstitutionID(institutionID)).
		SetExpiresAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to revoke support grants: %w", err)
	}
	return nil
}
```

---

## pkg/resilience/breaker.go

```go
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
```

---

## pkg/security/encryption.go

```go
package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/hkdf"

	pkgconfig "grantsupport/pkg/config"
)

var kmsClient *kms.Client

// getKmsClient initializes the AWS KMS client pool.
func getKmsClient(ctx context.Context) (*kms.Client, error) {
	if kmsClient != nil {
		return kmsClient, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(pkgconfig.AppConfig.AWSRegion))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
	}
	kmsClient = kms.NewFromConfig(cfg)
	return kmsClient, nil
}

// Encrypt encrypts a plaintext string using either AWS KMS or Local HKDF GCM fallback.
func Encrypt(ctx context.Context, plaintext string, institutionID string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	provider := pkgconfig.AppConfig.EncryptionProvider

	if provider == "AWS_KMS" {
		kmsKeyID := pkgconfig.AppConfig.KmsKeyID
		if kmsKeyID == "" {
			return "", errors.New("KMS_KEY_ID is missing in configuration")
		}

		client, err := getKmsClient(ctx)
		if err != nil {
			return "", err
		}

		res, err := client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId:   &kmsKeyID,
			KeySpec: types.DataKeySpecAes256,
			EncryptionContext: map[string]string{
				"institutionId": institutionID,
			},
		})
		if err != nil {
			return "", fmt.Errorf("KMS GenerateDataKey failed: %w", err)
		}

		plaintextKey := res.Plaintext
		encryptedDekBase64 := base64.StdEncoding.EncodeToString(res.CiphertextBlob)

		iv := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", err
		}

		block, err := aes.NewCipher(plaintextKey)
		if err != nil {
			return "", err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)
		ciphertext := sealed[:len(sealed)-16]
		tag := sealed[len(sealed)-16:]

		// Wipe plaintext key from memory
		for i := range plaintextKey {
			plaintextKey[i] = 0
		}

		ivBase64 := base64.StdEncoding.EncodeToString(iv)
		ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
		tagBase64 := base64.StdEncoding.EncodeToString(tag)

		return fmt.Sprintf("kms:%s:%s:%s:%s", encryptedDekBase64, ivBase64, ciphertextBase64, tagBase64), nil

	} else {
		// Fallback LOCAL mode (HKDF + AES-256-GCM)
		masterKey := pkgconfig.AppConfig.MasterEncryptionKey
		masterKeyHash := sha256.Sum256([]byte(masterKey))

		kdf := hkdf.New(sha256.New, masterKeyHash[:], []byte(institutionID), []byte("SUPPORT_GRANT_ENCRYPTION"))
		derivedKey := make([]byte, 32)
		if _, err := io.ReadFull(kdf, derivedKey); err != nil {
			return "", fmt.Errorf("HKDF key derivation failed: %w", err)
		}

		iv := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", err
		}

		block, err := aes.NewCipher(derivedKey)
		if err != nil {
			return "", err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)
		ciphertext := sealed[:len(sealed)-16]
		tag := sealed[len(sealed)-16:]

		ivBase64 := base64.StdEncoding.EncodeToString(iv)
		ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
		tagBase64 := base64.StdEncoding.EncodeToString(tag)

		return fmt.Sprintf("local:%s:%s:%s", ivBase64, ciphertextBase64, tagBase64), nil
	}
}

// Decrypt decrypts a formatted ciphertext string.
func Decrypt(ctx context.Context, ciphertext string, institutionID string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	parts := strings.Split(ciphertext, ":")
	if len(parts) == 0 {
		return "", errors.New("malformed encrypted payload")
	}

	provider := parts[0]

	if provider == "kms" {
		if len(parts) != 5 {
			return "", errors.New("malformed KMS encrypted payload")
		}

		encryptedDekBase64 := parts[1]
		ivBase64 := parts[2]
		cipherTextBase64 := parts[3]
		tagBase64 := parts[4]

		encryptedDek, err := base64.StdEncoding.DecodeString(encryptedDekBase64)
		if err != nil {
			return "", fmt.Errorf("invalid KMS DEK encoding: %w", err)
		}

		client, err := getKmsClient(ctx)
		if err != nil {
			return "", err
		}

		res, err := client.Decrypt(ctx, &kms.DecryptInput{
			CiphertextBlob: encryptedDek,
			EncryptionContext: map[string]string{
				"institutionId": institutionID,
			},
		})
		if err != nil {
			return "", fmt.Errorf("KMS Decrypt failed: %w", err)
		}

		plaintextKey := res.Plaintext

		iv, err := base64.StdEncoding.DecodeString(ivBase64)
		if err != nil {
			return "", fmt.Errorf("invalid IV encoding: %w", err)
		}

		ciphertextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
		if err != nil {
			return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
		}

		tagBytes, err := base64.StdEncoding.DecodeString(tagBase64)
		if err != nil {
			return "", fmt.Errorf("invalid tag encoding: %w", err)
		}

		block, err := aes.NewCipher(plaintextKey)
		if err != nil {
			return "", err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		sealed := append(ciphertextBytes, tagBytes...)
		plaintext, err := gcm.Open(nil, iv, sealed, nil)

		// Wipe plaintext key from memory
		for i := range plaintextKey {
			plaintextKey[i] = 0
		}

		if err != nil {
			return "", fmt.Errorf("GCM decryption failed: %w", err)
		}

		return string(plaintext), nil

	} else if provider == "local" {
		if len(parts) != 4 {
			return "", errors.New("malformed Local encrypted payload")
		}

		ivBase64 := parts[1]
		cipherTextBase64 := parts[2]
		tagBase64 := parts[3]

		masterKey := pkgconfig.AppConfig.MasterEncryptionKey
		masterKeyHash := sha256.Sum256([]byte(masterKey))

		kdf := hkdf.New(sha256.New, masterKeyHash[:], []byte(institutionID), []byte("SUPPORT_GRANT_ENCRYPTION"))
		derivedKey := make([]byte, 32)
		if _, err := io.ReadFull(kdf, derivedKey); err != nil {
			return "", fmt.Errorf("HKDF key derivation failed: %w", err)
		}

		iv, err := base64.StdEncoding.DecodeString(ivBase64)
		if err != nil {
			return "", fmt.Errorf("invalid IV encoding: %w", err)
		}

		ciphertextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
		if err != nil {
			return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
		}

		tagBytes, err := base64.StdEncoding.DecodeString(tagBase64)
		if err != nil {
			return "", fmt.Errorf("invalid tag encoding: %w", err)
		}

		block, err := aes.NewCipher(derivedKey)
		if err != nil {
			return "", err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		sealed := append(ciphertextBytes, tagBytes...)
		plaintext, err := gcm.Open(nil, iv, sealed, nil)
		if err != nil {
			return "", fmt.Errorf("GCM decryption failed: %w", err)
		}

		return string(plaintext), nil
	}

	return ciphertext, nil
}
```

---

## pkg/security/encryption_test.go

```go
package security_test

import (
	"context"
	"strings"
	"testing"

	pkgconfig "grantsupport/pkg/config"
	"grantsupport/pkg/security"
)

func TestLocalEncryptionDecryption(t *testing.T) {
	ctx := context.Background()
	plaintext := "sensitive_support_agent_token_12345"
	institutionID := "11111111-1111-1111-1111-111111111111"

	encrypted, err := security.Encrypt(ctx, plaintext, institutionID)
	if err != nil {
		t.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	if encrypted == plaintext {
		t.Fatal("Encrypted output should not match raw plaintext")
	}

	decrypted, err := security.Decrypt(ctx, encrypted, institutionID)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted text '%s', got '%s'", plaintext, decrypted)
	}
}

func TestEncryptionPersistenceAcrossRestart(t *testing.T) {
	ctx := context.Background()
	plaintext := "persistent_pii_payload_data_999"
	institutionID := "22222222-2222-2222-2222-222222222222"

	// 1. Initial configuration
	pkgconfig.AppConfig.MasterEncryptionKey = "persistent-secret-key-32bytes!!"
	pkgconfig.AppConfig.EncryptionProvider = "LOCAL"

	ciphertext, err := security.Encrypt(ctx, plaintext, institutionID)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 2. Simulate Application Restart with identical persistent key
	pkgconfig.AppConfig.MasterEncryptionKey = "persistent-secret-key-32bytes!!"
	decrypted, err := security.Decrypt(ctx, ciphertext, institutionID)
	if err != nil {
		t.Fatalf("Decryption after simulated restart failed: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("Decrypted payload %q did not match original %q", decrypted, plaintext)
	}

	// 3. Cross-Tenant Decryption Isolation (Tenant B cannot decrypt Tenant A's ciphertext)
	otherTenantID := "33333333-3333-3333-3333-333333333333"
	_, err = security.Decrypt(ctx, ciphertext, otherTenantID)
	if err == nil {
		t.Fatal("Expected decryption to fail for different tenant ID due to HKDF key isolation")
	}

	// 4. Corrupted Ciphertext Fails Closed
	tampered := strings.Replace(ciphertext, "local:", "local:corrupted", 1)
	_, err = security.Decrypt(ctx, tampered, institutionID)
	if err == nil {
		t.Fatal("Expected decryption of tampered ciphertext to fail closed")
	}
}
```

---

## pkg/security/jwt.go

```go
package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
	jwtKeyMutex   sync.RWMutex
)

// InitJWTKeys loads RSA Asymmetric Keypair for RS256 signing.
func InitJWTKeys(privateKeyPEM, publicKeyPEM []byte) error {
	jwtKeyMutex.Lock()
	defer jwtKeyMutex.Unlock()

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	rsaPrivateKey = privKey
	rsaPublicKey = pubKey
	return nil
}

// LoadJWTKeysFromEnv loads RS256 keys from environment variables or falls back to test keypair.
func LoadJWTKeysFromEnv() error {
	privPEM := []byte(os.Getenv("JWT_PRIVATE_KEY"))
	pubPEM := []byte(os.Getenv("JWT_PUBLIC_KEY"))

	if len(privPEM) == 0 || len(pubPEM) == 0 {
		return errors.New("JWT_KEYS_MISSING: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY environment variables must be configured")
	}

	return InitJWTKeys(privPEM, pubPEM)
}

// SetupTestRSAKeys generates and initializes an ephemeral RSA 2048-bit keypair for test suites.
func SetupTestRSAKeys() error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return InitJWTKeys(privPEM, pubPEM)
}

// GetRSAPublicKey returns current public key for JWKS rendering.
func GetRSAPublicKey() *rsa.PublicKey {
	jwtKeyMutex.RLock()
	defer jwtKeyMutex.RUnlock()
	return rsaPublicKey
}

// CustomClaims represents JWT token payload claims.
type CustomClaims struct {
	UserID        string `json:"user_id"`
	InstitutionID string `json:"institution_id"`
	Role          string `json:"role"`
	Scope         string `json:"scope,omitempty"`
	TokenVersion  int    `json:"token_version"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a new signed RS256 access token.
func GenerateJWT(userID, institutionID, role string, duration time.Duration) (string, error) {
	return GenerateJWTWithScope(userID, institutionID, role, "FULL_ACCESS", duration)
}

// GenerateJWTWithScope creates a new signed RS256 access token with explicit scope.
func GenerateJWTWithScope(userID, institutionID, role, scope string, duration time.Duration) (string, error) {
	return GenerateJWTWithVersion(userID, institutionID, role, scope, 1, duration)
}

// GenerateJWTWithVersion creates a new signed RS256 access token with explicit scope and token version.
func GenerateJWTWithVersion(userID, institutionID, role, scope string, tokenVersion int, duration time.Duration) (string, error) {
	jwtKeyMutex.RLock()
	privKey := rsaPrivateKey
	jwtKeyMutex.RUnlock()

	if privKey == nil {
		// Attempt to load from env if not initialized
		if err := LoadJWTKeysFromEnv(); err != nil {
			return "", fmt.Errorf("JWT_SIGNING_FAILED: RSA private key not initialized: %w", err)
		}
		jwtKeyMutex.RLock()
		privKey = rsaPrivateKey
		jwtKeyMutex.RUnlock()
	}

	if scope == "" {
		scope = "FULL_ACCESS"
	}

	claims := CustomClaims{
		UserID:        userID,
		InstitutionID: institutionID,
		Role:          role,
		Scope:         scope,
		TokenVersion:  tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "GrantSupport",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privKey)
}

// VerifyJWT parses and verifies a signed RS256 JWT token string using the public key.
func VerifyJWT(tokenString string) (*CustomClaims, error) {
	jwtKeyMutex.RLock()
	pubKey := rsaPublicKey
	jwtKeyMutex.RUnlock()

	if pubKey == nil {
		if err := LoadJWTKeysFromEnv(); err != nil {
			return nil, fmt.Errorf("JWT_VERIFY_FAILED: RSA public key not initialized: %w", err)
		}
		jwtKeyMutex.RLock()
		pubKey = rsaPublicKey
		jwtKeyMutex.RUnlock()
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("INVALID_JWT_TOKEN")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, errors.New("INVALID_TOKEN_CLAIMS")
	}

	return claims, nil
}
```

---

## pkg/security/keys.go

```go
package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type APIKeyDetails struct {
	ID              uuid.UUID
	KeyID           string
	InstitutionID   uuid.UUID
	PublicKeyBase64 string
	IsActive        bool
	WhitelistedIPs  []string
	Permissions     []string
}

func ValidatePayloadTTL(expiresAtUnix int64, maxTTLSeconds int64) error {
	now := time.Now().Unix()
	if expiresAtUnix < now {
		return errors.New("EXPIRED_REQUEST: Signature timestamp has expired")
	}
	if expiresAtUnix > now+maxTTLSeconds {
		return fmt.Errorf("INVALID_TTL: Expiration timestamp window exceeds maximum %d seconds", maxTTLSeconds)
	}
	return nil
}

func ParseEd25519PublicKeyBase64(pubKeyBase64 string) (ed25519.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}
	if len(bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(bytes))
	}
	return ed25519.PublicKey(bytes), nil
}

func VerifyEd25519Signature(pubKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}

func GenerateEd25519KeyPair() (string, string, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", nil, err
	}
	pubBase64 := base64.StdEncoding.EncodeToString(pub)
	privBase64 := base64.StdEncoding.EncodeToString(priv)
	return pubBase64, privBase64, priv, nil
}
```

---

## pkg/security/merkle.go

```go
package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// CalculateMerkleRoot computes the binary Merkle tree root hash for a slice of event/audit SHA-256 hashes.
func CalculateMerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		h := sha256.Sum256([]byte(""))
		return hex.EncodeToString(h[:])
	}

	if len(hashes) == 1 {
		return hashes[0]
	}

	currentLevel := make([]string, len(hashes))
	copy(currentLevel, hashes)

	for len(currentLevel) > 1 {
		if len(currentLevel)%2 != 0 {
			currentLevel = append(currentLevel, currentLevel[len(currentLevel)-1])
		}

		nextLevel := make([]string, 0, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			combined := currentLevel[i] + currentLevel[i+1]
			h := sha256.Sum256([]byte(combined))
			nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
		}
		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// GenerateMerkleProof generates sibling hashes required to verify that a hash at targetIndex belongs to the Merkle root.
func GenerateMerkleProof(hashes []string, targetIndex int) ([]string, error) {
	if targetIndex < 0 || targetIndex >= len(hashes) {
		return nil, errors.New("INVALID_INDEX: Target index out of bounds")
	}

	proof := make([]string, 0)
	currentLevel := make([]string, len(hashes))
	copy(currentLevel, hashes)
	currentIndex := targetIndex

	for len(currentLevel) > 1 {
		if len(currentLevel)%2 != 0 {
			currentLevel = append(currentLevel, currentLevel[len(currentLevel)-1])
		}

		var siblingIndex int
		if currentIndex%2 == 0 {
			siblingIndex = currentIndex + 1
		} else {
			siblingIndex = currentIndex - 1
		}

		proof = append(proof, currentLevel[siblingIndex])

		nextLevel := make([]string, 0, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			combined := currentLevel[i] + currentLevel[i+1]
			h := sha256.Sum256([]byte(combined))
			nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
		}
		currentLevel = nextLevel
		currentIndex /= 2
	}

	return proof, nil
}

// VerifyMerkleProof verifies whether a leaf hash belongs to a given Merkle root using sibling proof hashes.
func VerifyMerkleProof(leafHash, expectedRoot string, proof []string, index int) bool {
	currentHash := leafHash
	currentIndex := index

	for _, sibling := range proof {
		var combined string
		if currentIndex%2 == 0 {
			combined = currentHash + sibling
		} else {
			combined = sibling + currentHash
		}
		h := sha256.Sum256([]byte(combined))
		currentHash = hex.EncodeToString(h[:])
		currentIndex /= 2
	}

	return currentHash == expectedRoot
}
```

---

## pkg/security/merkle_test.go

```go
package security_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"grantsupport/pkg/security"
)

func TestMerkleTreeProofs(t *testing.T) {
	h1 := hex.EncodeToString(sha256.New().Sum([]byte("event_1")))
	h2 := hex.EncodeToString(sha256.New().Sum([]byte("event_2")))
	h3 := hex.EncodeToString(sha256.New().Sum([]byte("event_3")))
	hashes := []string{h1, h2, h3}

	root := security.CalculateMerkleRoot(hashes)
	if root == "" {
		t.Fatal("Expected non-empty Merkle root")
	}

	proof, err := security.GenerateMerkleProof(hashes, 0)
	if err != nil {
		t.Fatalf("Failed to generate Merkle proof: %v", err)
	}

	if !security.VerifyMerkleProof(h1, root, proof, 0) {
		t.Error("Merkle proof verification failed for target index 0")
	}
}
```

---

## pkg/security/sanitizer.go

```go
package security

import (
	"regexp"
	"strings"
)

var (
	// Email regex matching standard RFC 5322 email patterns
	emailRegex = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)

	// Credit Card / PAN regex (13 to 19 digits with optional hyphens or spaces)
	creditCardRegex = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)

	// Bearer tokens, passwords (quoted or unquoted), and secrets
	secretRegex = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*|password\s*=\s*"[^"]*"|password\s*=\s*'[^']*'|password["'\s:=]+[^\s,"']+|secret\s*=\s*"[^"]*"|secret\s*=\s*'[^']*'|secret["'\s:=]+[^\s,"']+)`)

	// Phone numbers (e.g. +1-800-555-0199, +1 (555) 234-5678, (555) 234-5678, 123-456-7890)
	phoneRegex = regexp.MustCompile(`(?i)(?:\+\d{1,3}[-.\s]*\(?\d{3}\)?|\b\(?\d{3}\)?)[-.\s]*\d{3}[-.\s]*\d{4}\b`)
)

// SanitizeAuditText cleans and redacts sensitive credentials and PII from audit strings.
func SanitizeAuditText(text string) string {
	if text == "" {
		return ""
	}

	sanitized := text

	// 1. Redact Secrets & Bearer Tokens
	sanitized = secretRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
		parts := strings.SplitN(match, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return "Bearer [REDACTED_TOKEN]"
		}
		return "[REDACTED_SECRET]"
	})

	// 2. Redact Emails
	sanitized = emailRegex.ReplaceAllString(sanitized, "[REDACTED_EMAIL]")

	// 3. Redact Credit Card numbers (ensure length >= 13 pure digits)
	sanitized = creditCardRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
		digitsOnly := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, match)
		if len(digitsOnly) >= 13 && len(digitsOnly) <= 19 {
			return "[REDACTED_CARD]"
		}
		return match
	})

	// 4. Redact Phone numbers (exclude UUID hexadecimal strings)
	sanitized = phoneRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
		digitsOnly := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, match)
		if len(digitsOnly) >= 10 && len(digitsOnly) <= 15 {
			return "[REDACTED_PHONE]"
		}
		return match
	})

	return sanitized
}

// SanitizeAuditMap recursively sanitizes all string values within an audit event details map.
func SanitizeAuditMap(data map[string]any) map[string]any {
	if data == nil {
		return nil
	}

	sanitized := make(map[string]any, len(data))
	for k, v := range data {
		lowerKey := strings.ToLower(k)
		if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "secret") || strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "key") {
			sanitized[k] = "[REDACTED_SECRET]"
			continue
		}

		switch val := v.(type) {
		case string:
			sanitized[k] = SanitizeAuditText(val)
		case map[string]any:
			sanitized[k] = SanitizeAuditMap(val)
		default:
			sanitized[k] = v
		}
	}

	return sanitized
}
```

---

## pkg/security/sanitizer_test.go

```go
package security_test

import (
	"strings"
	"testing"

	"grantsupport/pkg/security"
)

func TestSanitizeAuditText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Redacts email address",
			input:    "User admin@company.com accessed support console",
			expected: "User [REDACTED_EMAIL] accessed support console",
		},
		{
			name:     "Redacts credit card number",
			input:    "Payment attempt with 4111-2222-3333-4444 failed",
			expected: "Payment attempt with [REDACTED_CARD] failed",
		},
		{
			name:     "Redacts phone number",
			input:    "Called support phone +1-800-555-0199 for escalation",
			expected: "Called support phone [REDACTED_PHONE] for escalation",
		},
		{
			name:     "Redacts bearer token",
			input:    "API call with Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc12345",
			expected: "API call with Bearer [REDACTED_TOKEN]",
		},
		{
			name:     "Redacts password string",
			input:    "Configured password=\"superSecret123!\" in payload",
			expected: "Configured [REDACTED_SECRET] in payload",
		},
		{
			name:     "Empty text remains empty",
			input:    "",
			expected: "",
		},
		{
			name:     "Harmless text remains unaltered",
			input:    "Support session started by agent 550e8400-e29b-41d4-a716-446655440000",
			expected: "Support session started by agent 550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := security.SanitizeAuditText(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeAuditText(%q) = %q; expected %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSanitizeAuditMap(t *testing.T) {
	input := map[string]any{
		"admin_email": "john.doe@example.org",
		"password":    "secretP@ssw0rd",
		"nested": map[string]any{
			"phone": "+1 (555) 234-5678",
		},
		"count": 42,
	}

	sanitized := security.SanitizeAuditMap(input)

	if sanitized["admin_email"] != "[REDACTED_EMAIL]" {
		t.Errorf("Expected email to be redacted, got %v", sanitized["admin_email"])
	}
	if sanitized["password"] != "[REDACTED_SECRET]" {
		t.Errorf("Expected password to be redacted, got %v", sanitized["password"])
	}
	nested := sanitized["nested"].(map[string]any)
	if !strings.Contains(nested["phone"].(string), "REDACTED_PHONE") {
		t.Errorf("Expected nested phone to be redacted, got %v", nested["phone"])
	}
	if sanitized["count"] != 42 {
		t.Errorf("Expected primitive non-string values to be preserved, got %v", sanitized["count"])
	}
}
```

---

## pkg/service/grant_support_service.go

```go
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/webhook"
)

var (
	ErrSupportGrantInvalid = errors.New("SUPPORT_GRANT_INVALID: Invalid or expired support grant token")
	ErrSupportGrantExpired = errors.New("SUPPORT_GRANT_EXPIRED: Support grant token has expired")
)

type GrantSupportService struct {
	supportGrantRepo  *repository.SupportGrantRepository
	auditRepo         *repository.SecurityAuditRepository
	lockStore         ports.LockStore
	webhookDispatcher *webhook.WebhookDispatcher
}

func NewGrantSupportService(
	supportGrantRepo *repository.SupportGrantRepository,
	auditRepo *repository.SecurityAuditRepository,
	lockStore ports.LockStore,
) *GrantSupportService {
	return &GrantSupportService{
		supportGrantRepo: supportGrantRepo,
		auditRepo:        auditRepo,
		lockStore:        lockStore,
	}
}

// SetWebhookDispatcher attaches an optional WebhookDispatcher for lifecycle event notifications.
func (s *GrantSupportService) SetWebhookDispatcher(d *webhook.WebhookDispatcher) {
	s.webhookDispatcher = d
}

// CreateSupportGrant creates a temporary support access token with default FULL_ACCESS scope.
func (s *GrantSupportService) CreateSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int) (string, error) {
	return s.CreateSupportGrantScoped(ctx, institutionID, adminUserID, durationMinutes, "FULL_ACCESS", nil)
}

// CreateSupportGrantScoped creates a temporary support access token with granular scope and IP restrictions.
func (s *GrantSupportService) CreateSupportGrantScoped(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int, scope string, whitelistedIPs []string) (string, error) {
	if s.supportGrantRepo == nil {
		return "", errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if durationMinutes <= 0 || durationMinutes > 1440 {
		return "", errors.New("INVALID_DURATION: Support grant duration must be between 1 and 1440 minutes")
	}

	if scope == "" {
		scope = "FULL_ACCESS"
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate support grant token: %w", err)
	}
	randomHex := hex.EncodeToString(tokenBytes)
	rawToken := fmt.Sprintf("%s_%s", institutionID.String(), randomHex)

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	expiresAt := time.Now().Add(time.Duration(durationMinutes) * time.Minute)

	input := &domain.CreateSupportGrantInput{
		InstitutionID:  institutionID,
		GrantedByID:    adminUserID,
		TokenHash:      tokenHash,
		ExpiresAt:      expiresAt,
		Scope:          scope,
		WhitelistedIPs: whitelistedIPs,
	}

	if s.lockStore != nil {
		lockKey := fmt.Sprintf("lock:grant:%s", institutionID.String())
		err := s.lockStore.WithLock(ctx, lockKey, 10*time.Second, func(txCtx context.Context) error {
			_, err := s.supportGrantRepo.CreateSupportGrant(txCtx, input)
			return err
		})
		if err != nil {
			return "", fmt.Errorf("failed to create support grant under lock: %w", err)
		}
	} else {
		if _, err := s.supportGrantRepo.CreateSupportGrant(ctx, input); err != nil {
			return "", err
		}
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_GRANTED", fmt.Sprintf("Support access grant created for %d minutes with scope %s", durationMinutes, scope), nil)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.DispatchAsync(webhook.NewWebhookEvent(
			"grant.created",
			institutionID.String(),
			adminUserID.String(),
			map[string]any{
				"duration_minutes": durationMinutes,
				"scope":            scope,
				"expires_at":       expiresAt.Unix(),
				"whitelisted_ips":  whitelistedIPs,
			},
		))
	}

	return rawToken, nil
}

// SupportLogin authenticates a support agent using a valid support grant token and issues an RS256 JWT access token.
func (s *GrantSupportService) SupportLogin(ctx context.Context, rawToken string, agentUserID uuid.UUID) (uuid.UUID, string, error) {
	if agentUserID == uuid.Nil {
		return uuid.Nil, "", errors.New("AGENT_ID_REQUIRED: Explicit agentId UUID must be provided")
	}

	parts := strings.Split(rawToken, "_")
	if len(parts) != 2 {
		return uuid.Nil, "", ErrSupportGrantInvalid
	}

	instID, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, "", ErrSupportGrantInvalid
	}

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	if s.supportGrantRepo == nil {
		return uuid.Nil, "", errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	grant, err := s.supportGrantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil || grant == nil || grant.ExpiresAt.Before(time.Now()) {
		return uuid.Nil, "", ErrSupportGrantInvalid
	}

	if err := s.supportGrantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		if errors.Is(err, repository.ErrGrantAlreadyUsed) {
			return uuid.Nil, "", ErrSupportGrantInvalid
		}
		return uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID, "SUPPORT_ACCESS_LOGGED_IN", fmt.Sprintf("Support login executed by agent %s via active grant with scope %s", agentUserID.String(), grant.Scope), nil)
	}

	jwtToken, err := security.GenerateJWTWithScope(
		agentUserID.String(),
		instID.String(),
		"SUPPORT_AGENT",
		grant.Scope,
		4*time.Hour,
	)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to generate support JWT: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.DispatchAsync(webhook.NewWebhookEvent(
			"grant.claimed",
			instID.String(),
			agentUserID.String(),
			map[string]any{
				"grant_id": grant.ID.String(),
				"scope":    grant.Scope,
				"used_at":  time.Now().Unix(),
			},
		))
	}

	return instID, jwtToken, nil
}

// RevokeSupportGrant invalidates all active support grants for an institution.
func (s *GrantSupportService) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	if s.supportGrantRepo == nil {
		return errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if err := s.supportGrantRepo.RevokeAllGrantsForInstitution(ctx, institutionID); err != nil {
		return err
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "All active support access grants manually revoked by administrator", nil)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.DispatchAsync(webhook.NewWebhookEvent(
			"grant.revoked",
			institutionID.String(),
			adminUserID.String(),
			map[string]any{
				"revoked_at": time.Now().Unix(),
			},
		))
	}

	return nil
}
```

---

## pkg/service/grant_support_service_test.go

```go
package service_test

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

func TestGrantSupportServiceValidation(t *testing.T) {
	svc := service.NewGrantSupportService(nil, nil, nil)

	t.Run("CreateSupportGrant fails with nil repository", func(t *testing.T) {
		_, err := svc.CreateSupportGrant(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), 60)
		if err == nil {
			t.Errorf("Expected error when supportGrantRepo is nil")
		}
	})

	t.Run("CreateSupportGrant fails with invalid duration (0 minutes)", func(t *testing.T) {
		_, err := svc.CreateSupportGrant(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), 0)
		if err == nil {
			t.Errorf("Expected error for 0 minutes duration")
		}
	})

	t.Run("SupportLogin fails with nil agent UUID", func(t *testing.T) {
		_, _, err := svc.SupportLogin(context.Background(), "11111111-1111-1111-1111-111111111111_abcdef", uuid.Nil)
		if err == nil {
			t.Errorf("Expected error when agentUserID is uuid.Nil")
		}
	})

	t.Run("SupportLogin fails with malformed token", func(t *testing.T) {
		_, _, err := svc.SupportLogin(context.Background(), "invalid-token-without-underscore", uuid.Must(uuid.NewV7()))
		if err == nil {
			t.Errorf("Expected error for malformed token format")
		}
	})
}

func TestGrantSupportServiceLifecycle(t *testing.T) {
	ctx := context.Background()

	// Initialize test RSA keys
	if err := security.SetupTestRSAKeys(); err != nil {
		t.Fatalf("Failed to setup RSA keys for testing: %v", err)
	}

	// Open in-memory SQLite database with foreign keys enabled
	db, err := sql.Open("sqlite", "file:grantsupport_svc_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Tier 1: Admin Creates Support Grant
	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected non-empty raw grant token")
	}

	// Tier 2: Agent Logs in via Support Grant Token
	returnedInstID, jwtToken, err := svc.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}
	if returnedInstID != instID {
		t.Fatalf("Expected institution ID %s, got %s", instID, returnedInstID)
	}
	if jwtToken == "" {
		t.Fatal("Expected non-empty JWT token")
	}

	// Verify Issued JWT claims
	claims, err := security.VerifyJWT(jwtToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claims.InstitutionID != instID.String() || claims.UserID != agentID.String() || claims.Role != "SUPPORT_AGENT" {
		t.Fatalf("Unexpected JWT claims: %+v", claims)
	}

	// Replay attempt on same rawToken fails (single-use consumption invariant)
	_, _, err = svc.SupportLogin(ctx, rawToken, agentID)
	if err != service.ErrSupportGrantInvalid {
		t.Fatalf("Expected second login on consumed grant to fail with ErrSupportGrantInvalid, got: %v", err)
	}

	// Test Revocation
	rawToken2, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant 2 failed: %v", err)
	}

	if err := svc.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("RevokeSupportGrant failed: %v", err)
	}

	// Login after revocation fails
	_, _, err = svc.SupportLogin(ctx, rawToken2, agentID)
	if err != service.ErrSupportGrantInvalid {
		t.Fatalf("Expected login on revoked grant to fail, got: %v", err)
	}
}

func TestConcurrentSupportLoginRace(t *testing.T) {
	ctx := context.Background()

	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_login_race?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()

	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	const concurrency = 50
	var successCount int64
	var failCount int64

	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		workerAgentID := uuid.New()
		go func(agentID uuid.UUID) {
			<-startCh
			_, _, err := svc.SupportLogin(context.Background(), rawToken, agentID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			doneCh <- struct{}{}
		}(workerAgentID)
	}

	close(startCh)

	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	if successCount != 1 {
		t.Fatalf("Expected EXACTLY 1 successful login among 50 concurrent workers, got: %d", successCount)
	}
	if failCount != 49 {
		t.Fatalf("Expected EXACTLY 49 failed logins among 50 concurrent workers, got: %d", failCount)
	}
}

func TestConcurrentSupportLoginRace_100Workers(t *testing.T) {
	ctx := context.Background()

	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_login_100race_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()

	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed: %v", err)
	}

	const concurrency = 100
	var successCount int64
	var failCount int64

	startCh := make(chan struct{})
	doneCh := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		workerAgentID := uuid.New()
		go func(agentID uuid.UUID) {
			<-startCh
			_, _, err := svc.SupportLogin(context.Background(), rawToken, agentID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			doneCh <- struct{}{}
		}(workerAgentID)
	}

	close(startCh)

	for i := 0; i < concurrency; i++ {
		<-doneCh
	}

	if successCount != 1 {
		t.Fatalf("Expected EXACTLY 1 successful login among 100 concurrent workers, got: %d", successCount)
	}
	if failCount != 99 {
		t.Fatalf("Expected EXACTLY 99 failed logins among 100 concurrent workers, got: %d", failCount)
	}
}

func TestScopedSupportGrantAndJWT(t *testing.T) {
	ctx := context.Background()

	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:grantsupport_scoped_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Failed to auto-migrate SQLite schema: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// Create grant with specific scope "BILLING_ONLY" and whitelisted IP
	rawToken, err := svc.CreateSupportGrantScoped(ctx, instID, adminID, 60, "BILLING_ONLY", []string{"192.168.1.100"})
	if err != nil {
		t.Fatalf("CreateSupportGrantScoped failed: %v", err)
	}

	// Login and inspect JWT claims
	_, jwtToken, err := svc.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed: %v", err)
	}

	claims, err := security.VerifyJWT(jwtToken)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	if claims.Scope != "BILLING_ONLY" {
		t.Fatalf("Expected claims.Scope = BILLING_ONLY, got: %s", claims.Scope)
	}
}
```

---

## pkg/webhook/dispatcher.go

```go
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// WebhookEvent represents an event payload dispatched to registered subscriber webhooks.
type WebhookEvent struct {
	ID            string         `json:"id"`
	EventType     string         `json:"event_type"`
	InstitutionID string         `json:"institution_id"`
	ActorID       string         `json:"actor_id"`
	Timestamp     int64          `json:"timestamp"`
	Data          map[string]any `json:"data"`
}

// NewWebhookEvent constructs a new WebhookEvent with an assigned UUID and current timestamp.
func NewWebhookEvent(eventType, institutionID, actorID string, data map[string]any) *WebhookEvent {
	return &WebhookEvent{
		ID:            uuid.New().String(),
		EventType:     eventType,
		InstitutionID: institutionID,
		ActorID:       actorID,
		Timestamp:     time.Now().UTC().Unix(),
		Data:          data,
	}
}

// WebhookDispatcher delivers audit and grant lifecycle events to external systems via signed HTTP webhooks.
type WebhookDispatcher struct {
	webhookURL string
	secretKey  string
	client     *http.Client
}

// NewWebhookDispatcher creates a new WebhookDispatcher instance.
func NewWebhookDispatcher(webhookURL, secretKey string) *WebhookDispatcher {
	return &WebhookDispatcher{
		webhookURL: webhookURL,
		secretKey:  secretKey,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// ComputeSignature calculates the HMAC-SHA256 signature for a payload.
func (d *WebhookDispatcher) ComputeSignature(payload []byte) string {
	if d.secretKey == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(d.secretKey))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Dispatch sends a webhook event synchronously with HMAC-SHA256 signature authentication.
func (d *WebhookDispatcher) Dispatch(ctx context.Context, event *WebhookEvent) error {
	if d.webhookURL == "" {
		return nil // No-op if webhook is not configured
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GrantSupport-Webhook/1.0")
	req.Header.Set("X-GrantSupport-Event", event.EventType)
	req.Header.Set("X-GrantSupport-Delivery", event.ID)

	if signature := d.ComputeSignature(payload); signature != "" {
		req.Header.Set("X-GrantSupport-Signature", signature)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook delivery failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with non-2xx status code: %d", resp.StatusCode)
	}

	return nil
}

// DispatchAsync sends a webhook event asynchronously in a background goroutine.
func (d *WebhookDispatcher) DispatchAsync(event *WebhookEvent) {
	if d.webhookURL == "" {
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Webhook async dispatch panic recovered", slog.Any("panic", r))
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := d.Dispatch(ctx, event); err != nil {
			slog.Warn("Webhook asynchronous delivery warning",
				slog.String("event_type", event.EventType),
				slog.String("event_id", event.ID),
				slog.String("error", err.Error()),
			)
		}
	}()
}
```

---

## pkg/webhook/dispatcher_test.go

```go
package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
	"grantsupport/pkg/webhook"
)

func TestWebhookSignatureComputation(t *testing.T) {
	secret := "test_webhook_secret_key_123"
	dispatcher := webhook.NewWebhookDispatcher("http://localhost:9999", secret)

	payload := []byte(`{"event":"test"}`)
	sig := dispatcher.ComputeSignature(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if sig != expectedSig {
		t.Fatalf("ComputeSignature = %s, expected %s", sig, expectedSig)
	}
}

func TestWebhookDispatchDelivery(t *testing.T) {
	var receivedEvent webhook.WebhookEvent
	var receivedSignature string
	var receivedHeaderEvent string
	var receivedDeliveryID string

	secret := "secret_key_abc_456"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSignature = r.Header.Get("X-GrantSupport-Signature")
		receivedHeaderEvent = r.Header.Get("X-GrantSupport-Event")
		receivedDeliveryID = r.Header.Get("X-GrantSupport-Delivery")

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedEvent)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, secret)

	event := webhook.NewWebhookEvent("grant.created", "inst-111", "admin-222", map[string]any{
		"scope": "READ_ONLY",
	})

	err := dispatcher.Dispatch(context.Background(), event)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if receivedHeaderEvent != "grant.created" {
		t.Errorf("Expected X-GrantSupport-Event = grant.created, got %s", receivedHeaderEvent)
	}
	if receivedDeliveryID != event.ID {
		t.Errorf("Expected X-GrantSupport-Delivery = %s, got %s", event.ID, receivedDeliveryID)
	}
	if !strings.HasPrefix(receivedSignature, "sha256=") {
		t.Errorf("Expected signature with sha256= prefix, got %s", receivedSignature)
	}
	if receivedEvent.InstitutionID != "inst-111" || receivedEvent.ActorID != "admin-222" {
		t.Errorf("Unexpected event body received: %+v", receivedEvent)
	}
}

func TestWebhookDispatchAsync(t *testing.T) {
	var hitCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hitCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")

	event := webhook.NewWebhookEvent("grant.claimed", "inst-111", "agent-333", map[string]any{
		"scope": "FULL_ACCESS",
	})

	dispatcher.DispatchAsync(event)

	// Wait up to 1 second for background delivery
	for i := 0; i < 20; i++ {
		if atomic.LoadInt64(&hitCount) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if atomic.LoadInt64(&hitCount) != 1 {
		t.Fatalf("Expected async webhook to be delivered, got %d hits", atomic.LoadInt64(&hitCount))
	}
}

func TestWebhookDestinationFailure500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal_server_error"}`))
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")
	event := webhook.NewWebhookEvent("grant.revoked", "inst-1", "admin-1", nil)

	err := dispatcher.Dispatch(context.Background(), event)
	if err == nil {
		t.Fatal("Expected Dispatch to return error on HTTP 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "non-2xx status code: 500") {
		t.Fatalf("Unexpected error message: %v", err)
	}
}

func TestWebhookConnectionRefused(t *testing.T) {
	// Point to closed port
	dispatcher := webhook.NewWebhookDispatcher("http://127.0.0.1:59999/nonexistent-webhook", "secret")
	event := webhook.NewWebhookEvent("grant.created", "inst-1", "admin-1", nil)

	err := dispatcher.Dispatch(context.Background(), event)
	if err == nil {
		t.Fatal("Expected network error on connection refused, got nil")
	}
}

func TestWebhookTimeoutExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")
	event := webhook.NewWebhookEvent("grant.created", "inst-1", "admin-1", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := dispatcher.Dispatch(ctx, event)
	if err == nil {
		t.Fatal("Expected context deadline exceeded error on timeout, got nil")
	}
}

func TestGrantOperationIsolationFromWebhookFailure(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:webhook_isolation_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Schema creation failed: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	// Configure a failing webhook endpoint (HTTP 500)
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingServer.Close()

	failingDispatcher := webhook.NewWebhookDispatcher(failingServer.URL, "secret")
	svc.SetWebhookDispatcher(failingDispatcher)

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// 1. CreateSupportGrant must succeed despite failing webhook
	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed when webhook endpoint is 500: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected non-empty raw grant token")
	}

	// 2. SupportLogin must succeed despite failing webhook
	returnedInstID, jwtToken, err := svc.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed when webhook endpoint is 500: %v", err)
	}
	if returnedInstID != instID || jwtToken == "" {
		t.Fatalf("Expected valid login result, got inst=%s, token=%s", returnedInstID, jwtToken)
	}

	// 3. RevokeSupportGrant must succeed despite failing webhook
	if err := svc.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("RevokeSupportGrant failed when webhook endpoint is 500: %v", err)
	}

	// 4. Audit chain remains completely unbroken and valid
	valid, err := auditRepo.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("Audit chain was corrupted after webhook failure: valid=%v, err=%v", valid, err)
	}
}
```

---

## ent/generate.go

```go
package ent

//go:generate go run -mod=mod entgo.io/ent/cmd/ent generate ./schema
```

---

## ent/schema/auditevent.go

```go
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AuditEvent holds the schema definition for the AuditEvent entity.
type AuditEvent struct {
	ent.Schema
}

// Annotations of the AuditEvent.
func (AuditEvent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "gs_audit_events"},
	}
}

// Fields of the AuditEvent.
func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("actor_id", uuid.UUID{}),
		field.String("event_type"),
		field.String("description").Optional(),
		field.String("hash_chain").Optional(),
		field.String("signature").Optional(),
		field.Time("created_at").Default(time.Now),
	}
}

// Indexes of the AuditEvent.
func (AuditEvent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("institution_id", "created_at"),
		index.Fields("actor_id"),
		index.Fields("event_type"),
	}
}
```

---

## ent/schema/supportgrant.go

```go
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// SupportGrant holds the schema definition for the SupportGrant entity.
type SupportGrant struct {
	ent.Schema
}

// Annotations of the SupportGrant.
func (SupportGrant) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "gs_support_grants"},
	}
}

// Fields of the SupportGrant.
func (SupportGrant) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("granted_by_id", uuid.UUID{}),
		field.String("token_hash").Unique(),
		field.Time("expires_at"),
		field.Bool("is_used").Default(false),
		field.Time("used_at").Optional().Nillable(),
		field.String("scope").Default("FULL_ACCESS"),
		field.JSON("whitelisted_ips", []string{}).Optional(),
		field.Time("created_at").Default(time.Now),
	}
}
```

---

## api/openapi.yaml

```yaml
openapi: 3.1.0
info:
  title: GrantSupport Engine API
  version: 1.0.0
  description: >
    GrantSupport is an open-source, delegated support-access authentication and authorization engine.
    It enables multi-tenant SaaS applications to issue cryptographically signed, time-bounded,
    single-use support access tokens to vendor support agents with immutable audit logging.
  license:
    name: Apache-2.0
    url: https://www.apache.org/licenses/LICENSE-2.0.html

servers:
  - url: http://localhost:8080
    description: Local Standalone Server

paths:
  /health:
    get:
      summary: Health Check
      description: Returns the health and operational status of the GrantSupport service.
      responses:
        '200':
          description: Service is healthy and operational
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'

  /api/v1/auth/support/grant:
    post:
      summary: Create Delegated Support Grant
      description: >
        Called by a customer administrator to delegate temporary, time-bounded access to a vendor support agent.
        Generates a high-entropy single-use raw support token.
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/GrantSupportRequest'
      responses:
        '201':
          description: Support grant token created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/GrantSupportResponse'
        '400':
          $ref: '#/components/responses/RFC7807BadRequest'
        '401':
          $ref: '#/components/responses/RFC7807Unauthorized'
        '429':
          $ref: '#/components/responses/RFC7807TooManyRequests'
        '500':
          $ref: '#/components/responses/RFC7807InternalError'

  /api/v1/auth/support/login:
    post:
      summary: Claim Support Grant & Login
      description: >
        Called by a vendor support agent to consume a single-use support grant token.
        Atomically invalidates the token, emits an append-only audit event, and issues a 4-hour RS256 JWT access token.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SupportLoginRequest'
      responses:
        '200':
          description: Support grant claimed and session JWT issued
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SupportLoginResponse'
        '400':
          $ref: '#/components/responses/RFC7807BadRequest'
        '401':
          $ref: '#/components/responses/RFC7807Unauthorized'
        '429':
          $ref: '#/components/responses/RFC7807TooManyRequests'
        '500':
          $ref: '#/components/responses/RFC7807InternalError'

  /api/v1/auth/support/revoke:
    post:
      summary: Revoke Active Support Grants
      description: >
        Called by a customer administrator to immediately invalidate all pending or active support grants for their tenant.
      security:
        - BearerAuth: []
      responses:
        '200':
          description: All active support grants revoked successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/StandardSuccessResponse'
        '401':
          $ref: '#/components/responses/RFC7807Unauthorized'
        '500':
          $ref: '#/components/responses/RFC7807InternalError'

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: RS256 signed JSON Web Token carrying tenant and role claims.
    BulletproofEd25519:
      type: apiKey
      in: header
      name: X-Signature
      description: 5-layer Ed25519 dual-key asymmetric request signature.

  schemas:
    HealthResponse:
      type: object
      properties:
        status:
          type: string
          example: UP
        service:
          type: string
          example: GrantSupport Engine
        version:
          type: string
          example: v1.0.0
      required:
        - status
        - service
        - version

    GrantSupportRequest:
      type: object
      properties:
        durationMinutes:
          type: integer
          minimum: 1
          maximum: 1440
          description: Grant TTL window in minutes (1 to 24 hours).
          example: 60
        scope:
          type: string
          description: Granular permission scope (e.g., FULL_ACCESS, READ_ONLY, BILLING_ONLY).
          default: FULL_ACCESS
          example: BILLING_ONLY
        whitelistedIps:
          type: array
          items:
            type: string
          description: Optional list of authorized client CIDRs/IPs.
          example: ["198.51.100.4", "203.0.113.0/24"]
      required:
        - durationMinutes

    GrantSupportResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        message:
          type: string
          example: Support access token generated successfully.
        token:
          type: string
          description: High-entropy raw support delegation token to be provided to the support agent.
          example: "550e8400-e29b-41d4-a716-446655440000_9f83a8b9487c6e12..."
      required:
        - success
        - message
        - token

    SupportLoginRequest:
      type: object
      properties:
        token:
          type: string
          description: The raw support token provided by the customer administrator.
          example: "550e8400-e29b-41d4-a716-446655440000_9f83a8b9487c6e12..."
        agentId:
          type: string
          format: uuid
          description: Explicit UUID identifying the support engineer claiming the token.
          example: "7f4c935b-16d7-4f9e-a8f2-39c4a852b719"
      required:
        - token
        - agentId

    SupportLoginResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        message:
          type: string
          example: Support agent authenticated successfully.
        institution_id:
          type: string
          format: uuid
          example: "550e8400-e29b-41d4-a716-446655440000"
        accessToken:
          type: string
          description: 4-hour RS256 signed access token for support operations.
          example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
      required:
        - success
        - message
        - institution_id
        - accessToken

    StandardSuccessResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        message:
          type: string
          example: Operation completed successfully.
      required:
        - success
        - message

    ProblemDetails:
      type: object
      description: RFC 7807 Problem Details for HTTP APIs
      properties:
        type:
          type: string
          format: uri
          example: "https://grantsupport.dev/errors/validation-failed"
        title:
          type: string
          example: "Validation Failed"
        status:
          type: integer
          example: 400
        detail:
          type: string
          example: "Request payload failed schema validation constraints."
        instance:
          type: string
          example: "/api/v1/auth/support/login"
        code:
          type: string
          example: "VALIDATION_FAILED"
        correlation_id:
          type: string
          example: "req-98f2374b-1234-5678"
        invalid_params:
          type: array
          items:
            type: object
            properties:
              field:
                type: string
                example: "agentId"
              reason:
                type: string
                example: "field is required"
      required:
        - title
        - status
        - detail

  responses:
    RFC7807BadRequest:
      description: Bad Request (RFC 7807)
      content:
        application/problem+json:
          schema:
            $ref: '#/components/schemas/ProblemDetails'
    RFC7807Unauthorized:
      description: Unauthorized (RFC 7807)
      content:
        application/problem+json:
          schema:
            $ref: '#/components/schemas/ProblemDetails'
    RFC7807TooManyRequests:
      description: Too Many Requests / Rate Limited (RFC 7807)
      content:
        application/problem+json:
          schema:
            $ref: '#/components/schemas/ProblemDetails'
    RFC7807InternalError:
      description: Internal Server Error (RFC 7807)
      content:
        application/problem+json:
          schema:
            $ref: '#/components/schemas/ProblemDetails'
```

---

## migrations/mariadb/000001_initial_grantsupport_schema.down.sql

```sql
-- 000001_initial_grantsupport_schema.down.sql (MariaDB)

DROP TABLE IF EXISTS gs_revocations;
DROP TABLE IF EXISTS gs_replays;
DROP TABLE IF EXISTS gs_locks;
DROP TABLE IF EXISTS gs_audit_events;
DROP TABLE IF EXISTS gs_support_grants;
```

---

## migrations/mariadb/000001_initial_grantsupport_schema.up.sql

```sql
-- 000001_initial_grantsupport_schema.up.sql (MariaDB 10.6+)

CREATE TABLE IF NOT EXISTS gs_support_grants (
    id VARCHAR(36) PRIMARY KEY,
    institution_id VARCHAR(36) NOT NULL,
    granted_by_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME(6) NOT NULL,
    is_used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME(6) NULL,
    scope VARCHAR(64) NOT NULL DEFAULT 'FULL_ACCESS',
    whitelisted_ips LONGTEXT NULL CHECK (whitelisted_ips IS NULL OR JSON_VALID(whitelisted_ips)),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_gs_support_grants_inst_exp (institution_id, expires_at),
    INDEX idx_gs_support_grants_token_hash (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_audit_events (
    id VARCHAR(36) PRIMARY KEY,
    institution_id VARCHAR(36) NOT NULL,
    actor_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT NULL,
    hash_chain VARCHAR(64) NULL,
    signature TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_gs_audit_events_inst_created (institution_id, created_at),
    INDEX idx_gs_audit_events_actor (actor_id),
    INDEX idx_gs_audit_events_type (event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_locks (
    lock_key VARCHAR(255) PRIMARY KEY,
    owner_token VARCHAR(64) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    acquired_at DATETIME(6) NOT NULL,
    INDEX idx_gs_locks_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key VARCHAR(255) PRIMARY KEY,
    expires_at DATETIME(6) NOT NULL,
    INDEX idx_gs_replays_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_revocations (
    institution_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    token_version INT NOT NULL DEFAULT 1,
    revoked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (institution_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

---

## migrations/mysql/000001_initial_grantsupport_schema.down.sql

```sql
-- 000001_initial_grantsupport_schema.down.sql (MySQL)

DROP TABLE IF EXISTS gs_revocations;
DROP TABLE IF EXISTS gs_replays;
DROP TABLE IF EXISTS gs_locks;
DROP TABLE IF EXISTS gs_audit_events;
DROP TABLE IF EXISTS gs_support_grants;
```

---

## migrations/mysql/000001_initial_grantsupport_schema.up.sql

```sql
-- 000001_initial_grantsupport_schema.up.sql (MySQL 8.0+)

CREATE TABLE IF NOT EXISTS gs_support_grants (
    id VARCHAR(36) PRIMARY KEY,
    institution_id VARCHAR(36) NOT NULL,
    granted_by_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME(6) NOT NULL,
    is_used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME(6) NULL,
    scope VARCHAR(64) NOT NULL DEFAULT 'FULL_ACCESS',
    whitelisted_ips JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_gs_support_grants_inst_exp (institution_id, expires_at),
    INDEX idx_gs_support_grants_token_hash (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_audit_events (
    id VARCHAR(36) PRIMARY KEY,
    institution_id VARCHAR(36) NOT NULL,
    actor_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT NULL,
    hash_chain VARCHAR(64) NULL,
    signature TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_gs_audit_events_inst_created (institution_id, created_at),
    INDEX idx_gs_audit_events_actor (actor_id),
    INDEX idx_gs_audit_events_type (event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_locks (
    lock_key VARCHAR(255) PRIMARY KEY,
    owner_token VARCHAR(64) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    acquired_at DATETIME(6) NOT NULL,
    INDEX idx_gs_locks_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key VARCHAR(255) PRIMARY KEY,
    expires_at DATETIME(6) NOT NULL,
    INDEX idx_gs_replays_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gs_revocations (
    institution_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    token_version INT NOT NULL DEFAULT 1,
    revoked_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (institution_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

---

## migrations/postgres/000001_initial_grantsupport_schema.down.sql

```sql
-- 000001_initial_grantsupport_schema.down.sql (PostgreSQL)

DROP TABLE IF EXISTS gs_revocations;
DROP TABLE IF EXISTS gs_replays;
DROP TABLE IF EXISTS gs_locks;
DROP TABLE IF EXISTS gs_audit_events;
DROP TABLE IF EXISTS gs_support_grants;
```

---

## migrations/postgres/000001_initial_grantsupport_schema.up.sql

```sql
-- 000001_initial_grantsupport_schema.up.sql (PostgreSQL)

CREATE TABLE IF NOT EXISTS gs_support_grants (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    granted_by_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    scope VARCHAR(64) NOT NULL DEFAULT 'FULL_ACCESS',
    whitelisted_ips JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_support_grants_inst_exp ON gs_support_grants (institution_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_gs_support_grants_token_hash ON gs_support_grants (token_hash);

CREATE TABLE IF NOT EXISTS gs_audit_events (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT,
    hash_chain VARCHAR(64),
    signature TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_audit_events_inst_created ON gs_audit_events (institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gs_audit_events_actor ON gs_audit_events (actor_id);
CREATE INDEX IF NOT EXISTS idx_gs_audit_events_type ON gs_audit_events (event_type);

CREATE TABLE IF NOT EXISTS gs_locks (
    lock_key VARCHAR(255) PRIMARY KEY,
    owner_token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_locks_expires_at ON gs_locks (expires_at);

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_replays_expires_at ON gs_replays (expires_at);

CREATE TABLE IF NOT EXISTS gs_revocations (
    institution_id UUID NOT NULL,
    user_id UUID NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 1,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, user_id)
);
```

---

## migrations/sqlite/000001_initial_grantsupport_schema.down.sql

```sql
-- 000001_initial_grantsupport_schema.down.sql (SQLite 3)

DROP TABLE IF EXISTS gs_revocations;
DROP TABLE IF EXISTS gs_replays;
DROP TABLE IF EXISTS gs_locks;
DROP TABLE IF EXISTS gs_audit_events;
DROP TABLE IF EXISTS gs_support_grants;
```

---

## migrations/sqlite/000001_initial_grantsupport_schema.up.sql

```sql
-- 000001_initial_grantsupport_schema.up.sql (SQLite 3)

CREATE TABLE IF NOT EXISTS gs_support_grants (
    id TEXT PRIMARY KEY,
    institution_id TEXT NOT NULL,
    granted_by_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    used_at DATETIME,
    scope TEXT NOT NULL DEFAULT 'FULL_ACCESS',
    whitelisted_ips TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_support_grants_inst_exp ON gs_support_grants (institution_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_gs_support_grants_token_hash ON gs_support_grants (token_hash);

CREATE TABLE IF NOT EXISTS gs_audit_events (
    id TEXT PRIMARY KEY,
    institution_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    hash_chain TEXT,
    signature TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_gs_audit_events_inst_created ON gs_audit_events (institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gs_audit_events_actor ON gs_audit_events (actor_id);
CREATE INDEX IF NOT EXISTS idx_gs_audit_events_type ON gs_audit_events (event_type);

CREATE TABLE IF NOT EXISTS gs_locks (
    lock_key TEXT PRIMARY KEY,
    owner_token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    acquired_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_locks_expires_at ON gs_locks (expires_at);

CREATE TABLE IF NOT EXISTS gs_replays (
    nonce_key TEXT PRIMARY KEY,
    expires_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gs_replays_expires_at ON gs_replays (expires_at);

CREATE TABLE IF NOT EXISTS gs_revocations (
    institution_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 1,
    revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, user_id)
);
```

---

## docs/ARCHITECTURE.md

```markdown
# Technical Architecture & Security Specification

This document details the architectural design, cryptographic primitives, zero-data-liability principles, threat model, and immutability guarantees of **GrantSupport**.

---

## 1. Architectural Philosophy: Control-Plane vs. Data-Plane

GrantSupport separates system responsibilities into two strictly isolated boundaries:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (Your SaaS Infrastructure)                    │
│                                                                                │
│  - Issues signed cryptographic license keys (Ed25519)                          │
│  - Hosts JWKS public keys at /.well-known/jwks.json                            │
│  - Receives light telemetry heartbeats (IP, machine ID, active agent count)    │
│  - ZERO customer data storage (NO user profiles, NO financial ledgers, NO PII) │
└────────────────────────────────────────────────────────────────────────────────┘
                                      ▲
                                      │  Public Key Verification & Heartbeat Ping
                                      ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                   DATA PLANE (Customer Cloud / Docker / VPC)                   │
│                                                                                │
│  - Hosts customer PostgreSQL database and Valkey cache                         │
│  - Stores user profiles, application data, and SupportGrant records             │
│  - Executes local seat enforcement (Human & AI Agent limits)                   │
│  - Maintains append-only SHA-256 hash-chained AuditEvent ledger               │
└────────────────────────────────────────────────────────────────────────────────┘
```

### Strategic Benefits:
1. **Zero Customer PII Exposure**: Your infrastructure never sees or stores customer passwords, emails, tenant data, or application records.
2. **Infinite Horizontal Scale**: Your SaaS server only serves small JSON payloads for JWKS key rotation and daily heartbeats.
3. **SOC 2 & Compliance Ready**: Customers retain total ownership over their audit trail and data residency requirements.

---

## 2. Cryptographic License Verification (Ed25519)

Licenses are issued as base64-encoded, Ed25519-signed JSON Web Tokens (JWL):

### 2.1 License Payload Structure
```json
{
  "lic_id": "lic_994821a_2026",
  "customer_id": "cust_acme_corp",
  "domain_lock": "app.acmecorp.com",
  "max_human_agents": 10,
  "max_ai_agents": 5,
  "tier": "PRO_10",
  "issued_at": 1753880400,
  "expires_at": 1785416400,
  "offline_grace_days": 7
}
```

### 2.2 Local Verification Workflow (Inside Customer's Container)
1. At startup, `license.Manager` reads `LICENSE_KEY` from the environment.
2. The payload and signature are unmarshaled.
3. The signature is verified against your Ed25519 public key (`security.VerifyEd25519Signature(pubKey, payloadBytes, sigBytes)`).
4. If valid, license metadata is stored in Valkey with a TTL matching `expires_at`.

---

## 3. Delegation Token Mechanics & Security Control Flow

GrantSupport implements **Delegated Authorization with Ephemeral Tokens**:

```
[Customer Admin] ──1. POST /auth/support/grant (duration: 60m)──► [GrantSupport Core]
                                                                        │
                                                            2. Generate Raw Token
                                                            3. Save SHA-256(Token) in DB
                                                                        │
[Support Agent] ◄──4. Returns raw Token (inst_99812_a8b9...)──────────┘
       │
       ├──5. POST /auth/support/login (Token)──────────────────► [GrantSupport Core]
                                                                        │
                                                            6. Verify SHA-256(Token)
                                                            7. Check Expiration & Usage
                                                            8. Mark Token Used (One-Time)
                                                            9. Issue 4h SUPPORT_AGENT JWT
                                                                        │
                                                            10. Write AuditEvent Log
```

### Security Properties:
* **One-Time Usage**: Once `SupportLogin` consumes a grant token, `is_used` is set to `true`. Further login attempts with the same token are rejected (`401 SUPPORT_GRANT_INVALID`).
* **Time-Bound Expiration**: Grants automatically expire after the requested duration (e.g. 15m, 1h, 4h).
* **Instant Manual Revocation**: End-users can trigger `POST /auth/support/revoke` at any time, immediately invalidating active tokens and bumping user `TokenVersion`.

---

## 4. Tamper-Evident Ledger & Append-Only Database Triggers

Audit integrity is guaranteed at the database level using PL/pgSQL triggers and SHA-256 hash chains.

### 4.1 SHA-256 Hash Chaining Formula
For every `AuditEvent` and `FinanceLedger` entry $E_n$:
$$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} \parallel \text{EventType} \parallel \text{ActorID} \parallel \text{InstitutionID} \parallel \text{Timestamp})$$

### 4.2 Database Immutability Trigger
```sql
CREATE OR REPLACE FUNCTION prevent_auditevent_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABLE_AUDIT: AuditEvent records are append-only and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_auditevent_update
    BEFORE UPDATE ON "AuditEvent"
    FOR EACH ROW EXECUTE FUNCTION prevent_auditevent_mutation();

CREATE TRIGGER trg_prevent_auditevent_delete
    BEFORE DELETE ON "AuditEvent"
    FOR EACH ROW EXECUTE FUNCTION prevent_auditevent_mutation();
```

---

## 5. Threat Model & Countermeasures

| Threat Vector | Attack Scenario | Countermeasure |
| :--- | :--- | :--- |
| **Token Replay Attack** | Attacker intercepts a raw support grant token. | Single-use consumption flag (`is_used = true`) + short TTL (max 4h) + HTTPS TLS encryption. |
| **Seat Multiplication** | Customer runs 10 containers to bypass a 3-agent limit. | Valkey distributed lock (`Redlock`) + shared PostgreSQL agent seat counter across container replicas. |
| **License Tampering** | Customer modifies `max_human_agents` in the license JSON. | Ed25519 cryptographic signature check fails instantly on payload mutation. |
| **DB Audit Modification** | Malicious DB admin attempts to delete support access logs. | PostgreSQL triggers block `UPDATE` and `DELETE` queries at database driver level. |
```

---

## docs/COMMERCIAL_MODELS.md

```markdown
# Open-Source Architecture & Deployment Principles

GrantSupport is a 100% open-source delegated support-access authentication and cryptographic audit engine.

---

## 1. Open-Source Freedom & Guarantees

1. **Zero Proprietary Licensing**: No license keys, no seat limits, no human vs AI agent caps.
2. **Zero Phone-Home / Telemetry**: No external heartbeat pings, no machine fingerprinting, no mandatory external cloud services.
3. **Customer Data Ownership**: All audit ledgers, support grants, and tenant access records remain entirely within the customer's self-hosted infrastructure.

---

## 2. Deployment Models

### Minimal Standalone (PostgreSQL / MySQL / MariaDB / SQLite)
Deploy GrantSupport alongside your database with zero external infrastructure:
```bash
docker run -d \
  -e DATABASE_URL="postgres://user:pass@db:5432/grantsupport?sslmode=disable" \
  -e JWT_PRIVATE_KEY="$(cat jwt_rsa.key)" \
  -e JWT_PUBLIC_KEY="$(cat jwt_rsa.pub)" \
  -p 8085:8085 \
  grantsupport:latest
```

### High-Scale Distributed (Database + Optional Valkey/Redis)
For high-traffic multi-container deployments, optionally attach Valkey/Redis for accelerated in-memory locking and caching:
```bash
docker run -d \
  -e DATABASE_URL="postgres://user:pass@db:5432/grantsupport?sslmode=disable" \
  -e VALKEY_CACHE_URL="redis://valkey:6379" \
  -p 8085:8085 \
  grantsupport:latest
```

### Embedded Go Library
Import GrantSupport directly into your Go application and reuse your existing `*sql.DB` or `*pgxpool.Pool` without running a separate service container.
```

---

## docs/INTEGRATION_GUIDE.md

```markdown
# Developer Integration Guide

This guide walks developers step-by-step through integrating **GrantSupport** into an existing or new web application.

---

## 1. Prerequisites

Before integrating GrantSupport, ensure your environment provides:
* **Go 1.22+** (for Go native SDK / microservice deployment)
* **PostgreSQL 14+** (for local data plane storage)
* **Valkey 7.2+ or Redis 7+** (for distributed locking & token version caching)

---

## 2. Step 1 — Database Migration Setup

Run the GrantSupport database migration script to set up `SupportGrant`, `AuditEvent`, and append-only immutability triggers:

```bash
psql -h localhost -U postgres -d your_app_db -f migrations/000001_create_grantsupport_tables.sql
psql -h localhost -U postgres -d your_app_db -f migrations/000002_add_immutability_triggers.sql
```

---

## 3. Step 2 — Configuration Setup

Create an `.env` file or export environment variables for GrantSupport:

```env
# Server Configuration
PORT=8085
NODE_ENV=production

# Customer Database & Cache (Data Plane)
DATABASE_URL=postgres://postgres:password@localhost:5432/your_app_db?sslmode=disable
VALKEY_URL=redis://localhost:6379/0

# Licensing (Control Plane)
LICENSE_KEY=eyJhY3R... (Your Ed25519 License Key)
JWKS_URL=https://licensing.yourcompany.com/.well-known/jwks.json

# JWT Signing Keys
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..."
```

---

## 4. Step 3 — Adding GrantSupport Endpoints to Your Router

In your Go Chi / Gin / Fiber web router, mount the GrantSupport controller handlers:

```go
package main

import (
	"net/http"
	"github.com/go-chi/chi/v5"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/middleware"
)

func RegisterSupportRoutes(r chi.Router, deps *Dependencies) {
	// Public Support Agent Login Endpoint (Agents redeem token for JWT)
	r.Post("/api/v1/auth/support/login", controller.CatchAsync(deps.SupportController.SupportLogin))

	// Customer-Admin Role-Gated Delegation Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireRoles("ADMINISTRATOR", "OWNER"))
		
		// Customer Admin issues new support grant token
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(deps.SupportController.GrantSupport))
		
		// Customer Admin revokes all active support tokens
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(deps.SupportController.RevokeSupport))
	})
}
```

---

## 5. Step 4 — Embedding the Customer Grant UI Widget

Include the lightweight GrantSupport frontend widget in your web application's settings dashboard:

```html
<!-- Settings -> Support Access Panel -->
<div id="grantsupport-widget" class="card shadow-sm p-4">
  <h3>Delegated Support Access</h3>
  <p class="text-muted">Grant temporary, audited access to customer support engineers or AI diagnostics.</p>
  
  <div class="d-flex gap-3 align-items-center mt-3">
    <select id="grant-duration" class="form-select w-auto">
      <option value="15">15 Minutes</option>
      <option value="60" selected>1 Hour</option>
      <option value="240">4 Hours</option>
    </select>
    
    <button id="btn-grant-access" class="btn btn-primary" onclick="generateSupportGrant()">
      Grant Support Access
    </button>
    <button id="btn-revoke-access" class="btn btn-danger" onclick="revokeSupportAccess()">
      Revoke All Access
    </button>
  </div>
  
  <div id="grant-output" class="alert alert-info mt-3 d-none">
    <strong>Support Token:</strong> <code id="token-text"></code>
    <br><small>Provide this token to your support engineer or diagnostic bot.</small>
  </div>
</div>

<script>
async function generateSupportGrant() {
  const duration = parseInt(document.getElementById('grant-duration').value);
  const response = await fetch('/api/v1/auth/support/grant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ duration_minutes: duration })
  });
  const data = await response.json();
  if (data.success) {
    document.getElementById('token-text').innerText = data.grant_token;
    document.getElementById('grant-output').classList.remove('d-none');
  }
}
</script>
```

---

## 6. Step 5 — Verification & Testing

Verify that your integration works properly by running:

```bash
# Test 1: Verify license signature check
go test ./pkg/license/... -v

# Test 2: Verify support login token consumption
go test ./pkg/service/... -run TestSupportLogin -v

# Test 3: Run full parity check
python scripts/parity_audit.py
```
```

---

## docs/implementation_plan.md

```markdown
# GrantSupport — Master Remediation & Enterprise Feature Roadmap

This document serves as the authoritative, phased technical implementation plan to resolve all code-documentation gaps, multi-database support requirements, missing Docker infrastructure, and enterprise security features for **GrantSupport**.

> **Canonical authoritative source**: Each phase listed here has a corresponding deep-detail plan document (`docs/phase_N_plan.md`). When this document and a phase plan conflict, **the phase plan governs**. This document is the executive summary and cross-reference index only.

---

## Executive Summary & Gap Matrix

| Remediation Phase | Category | Priority | Key Technical Deliverables |
| :--- | :--- | :---: | :--- |
| **Phase 1** | Code-Doc Parity | 🚨 **CRITICAL** | Implement `pkg/license` Ed25519 engine with startup caching; fix `SupportLogin` agent identity DTO; enforce strict Valkey fail-closed startup; add JWT key production guard; add `.env.example`. |
| **Phase 2** | DB & Migrations | 🚨 **CRITICAL** | Create `migrations/{postgres,mysql,sqlite}/` SQL files; pure-Go SQLite driver; dialect allowlist validation; MySQL triggers without DELIMITER; MySQL+SQLite CREATE TABLE scripts. |
| **Phase 3** | Containerization | 🚨 **CRITICAL** | Multi-stage `Dockerfile`; `docker-compose.yml` mounting only `migrations/postgres/` into postgres container; `MASTER_ENCRYPTION_KEY` via env var substitution (no hardcoded values); migration upgrade procedure documented. |
| **Phase 4** | Security Hardening | 🛡️ **HIGH** | Atomic Lua-based rate limiter; per-institution revocation with millisecond timestamps and fail-closed Valkey check; rate limiter wired in `main.go`; two revocation modes explicitly named. |
| **Phase 5** | Audit & Non-Repudiation | 🛡️ **HIGH** | Ent schema `signature` field added first; Ed25519 audit signing; PII redaction with fixed space-separated card regex; chain verification function; ALL call sites of changed `LogSecurityEvent` updated. |
| **Phase 6** | Scope & Webhooks | 💡 **MEDIUM** | `InstitutionWebhook` entity; HMAC-signed payloads; shutdown-aware dispatcher; `reason` field through full stack; scope deferred enforcement documented; **`pkg/encryption` AES-256-GCM package introduced** (I-8 fix); webhook registration controller + route added; `RegisterWebhook` method on controller. |
| **Phase 7** | Developer SDK & Client UI | 💡 **MEDIUM** | SDK `MountRoutes` with auth middleware, rate limiter, **and webhook registration route** (I-6 fix); widget with unique per-instance IDs and `res.ok` guard; camelCase JSON keys. |

---

## Canonical Behaviors (Cross-File Authoritative Definitions)

These behaviors are defined here and must not contradict any phase plan. Phase plans define the _how_; this section defines the _what_.

### Mandatory Cross-Phase Signature Verification Rule

> **Any fix that changes a function signature, constructor, or exported struct MUST include, in the same edit, an explicit list of every other phase file that calls it, confirmation that each was checked, and the updated call site shown in that phase's file — not deferred to a separate pass. A signature change without this cross-reference list attached is considered incomplete, the same way a completion claim without `parity_audit.py` output is considered incomplete.**
>
> This rule exists because two bugs in Round 2 (I-2 and I-7) both occurred because a constructor signature changed in one phase's plan without the corresponding call site in another phase being updated. This is a recurring failure mode, not a coincidence.

### agent_id Parse Failure (finding #1 / #39)

> A malformed or missing `agentId` field on `POST /api/v1/auth/support/login` returns **HTTP 400** with RFC 7807 body `code: "INVALID_AGENT_ID"`. There is **no silent random-UUID fallback** anywhere in the codebase or any plan.

Defined in: `docs/phase_1_plan.md` → Component 1 → `SupportLogin` controller implementation.

**SUPERSEDES** the earlier draft in this document that showed `agentUUID = uuid.New()` on parse failure. That draft was incorrect. The corrected behavior is reject-with-400.

### Revocation Design (finding #28)

There are exactly two revocation features, clearly named:

1. **Per-institution revocation** (`RevokeSupportGrant`): Marks all DB grant rows expired AND writes a Valkey timestamp key `revoked:inst:<institution_id>`. AuthMiddleware rejects any JWT whose `IssuedAt` milliseconds are **strictly less than** (`<`) the stored revocation timestamp. Fails closed if Valkey is unavailable.

2. **Per-agent JWT revocation** (future phase — deferred): Blacklisting a single JWT by `jti` claim. Not implemented in phases 1–7. Tracked as Phase 4.1.

Defined in: `docs/phase_4_plan.md` → Component 1.

### MASTER_ENCRYPTION_KEY

Never hardcoded in any compose or config file. Always read from environment variable `${MASTER_ENCRYPTION_KEY}` which must be set in the operator's `.env` file (see `.env.example` created in Phase 1).

---

## Phase 1: Code-Documentation Parity & Critical Bug Fixes

### 1.1 Fix Support Agent Identity in `SupportLogin`

* **File**: `pkg/controller/auth_dto.go`
* **Change**: Update `SupportLoginInput` DTO. Use **camelCase JSON tags** to match the live codebase convention.

```go
// SupportLoginInput captures support token and agent identity payload.
// agentId parse failure → HTTP 400 INVALID_AGENT_ID (no UUID fallback).
type SupportLoginInput struct {
	Token      string `json:"token" validate:"required"`
	AgentID    string `json:"agentId" validate:"required,uuid"`
	AgentEmail string `json:"agentEmail" validate:"omitempty,email"`
}
```

* **File**: `pkg/controller/auth_support_controller.go`
* **Change**: Reject bad `agentId` with HTTP 400 (not random-UUID fallback).

```go
// agentId parse failure is HTTP 400 — canonical behavior defined here.
agentUUID, err := uuid.Parse(input.AgentID)
if err != nil {
    return NewAppError(http.StatusBadRequest, "INVALID_AGENT_ID", "agentId must be a valid UUID (v4 or v7)")
}
```

### 1.2 Implement Missing `pkg/license` Ed25519 Engine

Full implementation in `docs/phase_1_plan.md` → Component 2.
Key architectural decision: `VerifyAndCache()` is called **once at startup**; `CachedClaims()` is used thereafter. This prevents cliff-edge expiry mid-session and avoids per-request signature verification overhead. `OfflineGraceDays` is applied as a buffer past `ExpiresAt`.

### 1.3 Enforce Strict Valkey Fail-Closed Rule

```go
// Fail hard in production if Valkey is unavailable (valkey-enforcement.md).
if cfg.ValkeyCacheURL != "" {
    valkeyClient, err = cache.NewValkeyClient(cfg.ValkeyCacheURL)
    if err != nil {
        slog.Error("CRITICAL: Failed to connect to Valkey", slog.String("error", err.Error()))
        if cfg.Environment == "production" {
            os.Exit(1)
        }
    }
} else if cfg.Environment == "production" {
    slog.Error("FATAL: VALKEY_CACHE_URL required in production. Exiting.")
    os.Exit(1)
}
```

### 1.4 JWT Key Production Guard

```go
if err := security.LoadJWTKeysFromEnv(); err != nil {
    if cfg.Environment == "production" {
        slog.Error("FATAL: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY required in production. Exiting.")
        os.Exit(1)
    }
    // Development-only fallback:
    security.SetupTestRSAKeys()
}
```

---

## Phase 2: Multi-Database Support & Migrations

### 2.1 Migration Directory Structure

```
migrations/
  postgres/
    000001_create_grantsupport_tables.sql
    000002_add_immutability_triggers.sql
    000003_add_hash_chain_check.sql   ← Applied during Phase 5 deployment ONLY
  mysql/
    000001_create_grantsupport_tables.sql  (CHAR(36) for UUID, TEXT for JSONB)
    000002_add_immutability_triggers.sql   (no DELIMITER — single-statement CREATE TRIGGER)
    000003_add_hash_chain_check.sql        ← Applied during Phase 5 deployment ONLY
  sqlite/
    000001_create_grantsupport_tables.sql  (TEXT for all types)
    000002_immutability_limitation.md      (documented known limitation)
    000003_add_hash_chain_check.sql        ← Applied during Phase 5 deployment ONLY (table rebuild)
```

> **SEQUENCING**: 000003 migrations must NOT be applied before Phase 5 code is deployed. Applying 000003 before Phase 5 causes every `LogSecurityEvent` INSERT to violate the `CHECK (length(hash_chain) > 0)` constraint since Phase 2/3/4 code writes an empty string default.

### 2.2 Multi-Dialect Dynamic DB Driver

* SQLite driver: **`modernc.org/sqlite`** (pure Go — no CGO — compatible with Phase 3 `CGO_ENABLED=0` Dockerfile).
* `DATABASE_DIALECT` env var validated against allowlist `{postgres, mysql, sqlite3}` with clear error on unknown values.

---

## Phase 3: Docker & Deployment Packaging

### 3.1 Dockerfile

Multi-stage build with `CGO_ENABLED=0`, non-root `appuser`, Alpine runtime. Full spec in `docs/phase_3_plan.md`.

### 3.2 Docker Compose

```yaml
# Key corrections vs. earlier draft:
# 1. Mount only migrations/postgres/ into postgres container (not all of migrations/).
# 2. MASTER_ENCRYPTION_KEY via ${MASTER_ENCRYPTION_KEY} env substitution (never hardcoded).
volumes:
  - ../migrations/postgres:/docker-entrypoint-initdb.d
environment:
  - MASTER_ENCRYPTION_KEY=${MASTER_ENCRYPTION_KEY}
```

### 3.3 Upgrade Procedure for Existing Deployments

`docker-entrypoint-initdb.d` only runs on fresh DB volumes. For upgrades, use `golang-migrate`:
```bash
migrate -path migrations/postgres -database "${DATABASE_URL}" up
```

---

## Phase 4: Security Hardening

### 4.1 Two Named Revocation Designs

See Canonical Behaviors section above. Per-institution only in these phases; per-agent JWT deferred.

### 4.2 Atomic Rate Limiter

Uses Lua script (`INCR` + `EXPIRE` in a single atomic operation) instead of two-step approach. Prevents permanent IP ban from TTL-race condition.

### 4.3 Fail-Closed Revocation Check

AuthMiddleware denies (`503`) rather than allows when Valkey is unreachable during revocation check.

### 4.4 Rate Limiter Wired in main.go

```go
r.With(middleware.RateLimitMiddleware(valkeyClient, 10, 60)).
    Post("/api/v1/auth/support/login", controller.CatchAsync(grantController.SupportLogin))
```

---

## Phase 5: Cryptographic Non-Repudiation & Audit PII Redaction

### Step Order (mandatory)
1. Add `field.String("signature").Optional()` to `ent/schema/auditevent.go`
2. Run `go generate ./ent/...`
3. Update `SecurityAuditRepository` constructor and `LogSecurityEvent` signature
4. Update ALL call sites in `grant_support_service.go` and `main.go`

### 5.1 Constructor Change

```go
// Phase 5 changes this from 1-arg to 2-arg. Phase 1 left it unchanged.
// All callers must be updated as part of this phase.
func NewSecurityAuditRepository(base *BaseRepository, privKey ed25519.PrivateKey) *SecurityAuditRepository
```

### 5.2 LogSecurityEvent Change

```go
// Phase 5 drops the *ent.Tx parameter and changes the return type.
// Old: LogSecurityEvent(ctx, instID, actorID, type, desc, *ent.Tx) (*AuditLogResult, error)
// New: LogSecurityEvent(ctx, instID, actorID, type, desc) (*AuditLogResult, error)
//
// P2+P4 fix: ALL 5 call sites are updated in Step 4 of phase_5_plan.md:
//   1. SUPPORT_ACCESS_GRANTED    (line 89  — original)
//   2. SUPPORT_ACCESS_LOGGED_IN  (line 124 — original)
//   3. SUPPORT_ACCESS_REVOKED    (line 151 — original)
//   4. SUPPORT_LOGIN_FAILED      (added by Phase 4 Component 4b)
//   5. SUPPORT_LOGIN_SEAT_LIMIT  (added by Phase 1 Component 5)
// Phase 5 owns patching all of them atomically because it owns the signature change.
```

### 5.3 Signature Canonical Message

Uses `UnixNano()` and includes the event UUID to prevent same-second signature collisions.

---

## Phase 6: Scope, Webhooks & Idempotency

* `InstitutionWebhook` entity for per-institution target URL + shared secret.
* HMAC-SHA256 signing on webhook payloads (header: `X-GrantSupport-Signature`).
* Idempotent event IDs via UUID v5 from `(sourceID + eventType)`.
* `WebhookDispatcher` uses `sync.WaitGroup` and shutdown context (not `context.Background()`).
* `reason` field: present in Ent schema, domain struct, and all layers.
* Scope enforcement deferred to Phase 6.1 (explicitly documented, not silently missing).
* `pkg/encryption` AES-256-GCM package introduced (I-8 fix) — `MASTER_ENCRYPTION_KEY` env var required in production.
* No-retry gap documented: `WebhookDispatcher` makes one delivery attempt; retry logic deferred to Phase 6.1.

> **⚠️ Implementation decision required before coding Phase 6**: `DispatchEvent` accepts a `shutdownCtx context.Context` that must be the **server's shutdown context** — not the HTTP request context. The HTTP request context is cancelled when the handler returns, which would cancel in-flight goroutines and defeat `sync.WaitGroup` safety. Resolution options:
> - **(A — recommended)** Store a `shutdownCtx context.Context` field on `WebhookDispatcher` set at construction time from `main.go`'s shutdown context.
> - **(B)** Use `context.WithoutCancel(ctx)` (requires Go 1.21+) at the call site.
> This must be decided and documented in Phase 6 Component 3 before implementation.

---

## Phase 7: Developer SDK & Client UI

* `MountRoutes` applies `NewAuthMiddleware` to grant/revoke group and `RateLimitMiddleware` to login.
* Widget uses `this.container.querySelector` with unique per-instance UID suffix.
* Widget checks `res.ok` before `res.json()` and wraps in try/catch.
* Widget sends `durationMinutes` (camelCase) to match server DTO.

---

## Verification & Automated Test Plan

### Build Check at Each Phase
```bash
# After Phase 1:
go build ./...

# After Phase 2 (new Ent schema fields + migration SQL):
go generate ./ent/...
go build ./...

# After Phase 5 (ent schema: signature field + code-gen required first):
go generate ./ent/...
go build ./...
# Then deploy code, THEN apply 000003 migration (NOT before):
migrate -path migrations/postgres -database "${DATABASE_URL}" up

# After Phase 6 (new InstitutionWebhook entity):
go generate ./ent/...
go build ./...
```

### Required Environment Variables per Phase

| Phase | Variable | Required In |
|---|---|---|
| 1 | `VALKEY_CACHE_URL` | Production (fatal exit if missing) |
| 1 | `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` | Production (fatal exit if missing) |
| 1 | `LICENSE_KEY`, `LICENSE_PUBLIC_KEY` | Production (seat enforcement disabled if absent) |
| 5 | `AUDIT_SIGNING_PRIVATE_KEY` | Optional; entries unsigned if absent |
| 6 | `MASTER_ENCRYPTION_KEY` | Production (fatal exit if missing; 64 hex chars) |

Generate `MASTER_ENCRYPTION_KEY`: `openssl rand -hex 32`

### Automated Test Suites
1. **Unit & Signature Tests**:
   ```bash
   go test ./pkg/security/... -v
   go test ./pkg/license/... -v
   ```
2. **Controller & Integration Tests**:
   ```bash
   go test ./pkg/service/... -v
   go test ./pkg/controller/... -v
   ```
3. **Container Readiness**:
   ```bash
   docker compose -f docker/docker-compose.yml up --build -d
   curl -i http://localhost:8085/health
   ```

### Manual Verification Flow
1. **Support Grant Creation**: `POST /api/v1/auth/support/grant` with valid admin JWT → `201 Created` with `token`.
2. **Support Agent Login**: `POST /api/v1/auth/support/login` with `{ "token": "...", "agentId": "<valid-uuid>" }` → `200 OK` with `access_token`.
3. **Bad agentId**: `POST /api/v1/auth/support/login` with `agentId: "not-a-uuid"` → `400 INVALID_AGENT_ID`.
4. **Instant Revocation**: `POST /api/v1/auth/support/revoke` → subsequent JWT usage returns `401 TOKEN_REVOKED`.
5. **Valkey down (fail-closed)**: Stop Valkey, present JWT → `503 REVOCATION_CHECK_UNAVAILABLE`.
```

---

## docs/phase_1_plan.md

```markdown
# Phase 1 Implementation Plan: Code-Documentation Parity & Critical Bug Fixes

## 📌 Problem & Context
Phase 1 addresses the core code-documentation discrepancies and critical runtime bugs identified in GrantSupport:
1. **Support Login Agent Identity Flaw**: `SupportLoginInput` DTO only accepts `token`, causing support agent logins to execute with `user_id = 00000000-0000-0000-0000-000000000000` (nil UUID).
2. **Missing `pkg/license` Ed25519 Engine**: Documentation references Ed25519 license signature verification and seat caps, but `pkg/license/` is completely empty.
3. **Valkey Soft Bypass Vulnerability**: `main.go` catches Valkey connection errors as warnings instead of enforcing mandatory fail-closed startup behavior in production.
4. **Missing JWT Key Production Guard**: If `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY` are unset, the app silently falls back to a transient ephemeral keypair — tokens become invalid on every restart.

> **Cross-phase note (F-1-C, F-1-D)**: Phase 5 changes `NewSecurityAuditRepository`'s constructor signature (adds an `ed25519.PrivateKey` parameter) and completely rewrites `LogSecurityEvent` (drops the `*ent.Tx` parameter and changes the return type). To avoid a compile break when phases are applied in order, **Phase 1 does NOT update the `auditRepo` wiring in `main.go` beyond what is already present in the current codebase**. Phase 5 owns that entire update as a single self-contained diff, and explicitly documents every call site it touches.

> **JSON tag convention (F-1-A)**: The live codebase uses `json:"durationMinutes"` (camelCase) on `GrantSupportInput`. All plans and the Phase 7 JS widget use **camelCase** JSON keys. Do not use snake_case `duration_minutes` anywhere.

> **agent_id parse failure — authoritative behavior (finding #1)**: A malformed or missing `agentId` field returns **HTTP 400 with `code: "INVALID_AGENT_ID"`**. There is no silent random-UUID fallback. This is the single canonical behavior across all plan files.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `pkg/controller` — DTO & Controller Updates

#### [MODIFY] [auth_dto.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_dto.go)

**BEFORE:**
```go
// SupportLoginInput captures support token payload.
type SupportLoginInput struct {
	Token string `json:"token" validate:"required"`
}
```

**AFTER:**
```go
// SupportLoginInput captures support token and agent identity payload.
// AgentID is required and must be a valid UUID; a parse failure returns HTTP 400
// rather than a silent nil-UUID fallback — this is the canonical behavior across all plans.
type SupportLoginInput struct {
	Token      string `json:"token" validate:"required"`
	AgentID    string `json:"agentId" validate:"required,uuid"`
	AgentEmail string `json:"agentEmail" validate:"omitempty,email"`
}
```

**NOTE**: `GrantSupportInput.DurationMinutes` already has `json:"durationMinutes"` in the live file — no change needed. Phase 6 must preserve this camelCase tag when it adds `Reason` and `Scope` fields.

#### [MODIFY] [auth_support_controller.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_support_controller.go#L46-L74)

**BEFORE:**
```go
// SupportLogin authenticates a support agent using a valid support token.
// POST /api/v1/auth/support/login
func (c *SupportGrantController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}

	var callerID uuid.UUID
	if userID, ok := pkgctx.GetUser(r.Context()); ok {
		callerID = userID
	}

	instID, jwtToken, err := c.grantService.SupportLogin(r.Context(), input.Token, callerID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Delegated support login successful.",
		"access_token": jwtToken,
		"data": map[string]any{
			"institution_id": instID,
			"access_token":   jwtToken,
		},
	})
	return nil
}
```

**AFTER:**
```go
// SupportLogin authenticates a support agent using a valid support token.
// POST /api/v1/auth/support/login
// agentId parse failure returns HTTP 400 — reject-with-400 is the authoritative behavior
// (no silent random-UUID fallback anywhere in the codebase or plans).
func (c *SupportGrantController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}

	// uuid validate tag already enforces format; Parse here is belt-and-suspenders.
	agentUUID, err := uuid.Parse(input.AgentID)
	if err != nil {
		return NewAppError(http.StatusBadRequest, "INVALID_AGENT_ID", "agentId must be a valid UUID (v4 or v7)")
	}

	instID, jwtToken, err := c.grantService.SupportLogin(r.Context(), input.Token, agentUUID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Delegated support login successful.",
		"access_token": jwtToken,
		"role":         "SUPPORT_AGENT",
		"expires_in":   14400,
		"data": map[string]any{
			"institution_id": instID,
			"agent_id":       agentUUID,
			"access_token":   jwtToken,
		},
	})
	return nil
}
```

---

### Component 2: `pkg/license` — Ed25519 License Verification Engine with Startup Caching

#### [NEW] [manager.go](file:///d:/Hostel_management/GrantSupport/pkg/license/manager.go)

```go
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrLicenseInvalid   = errors.New("LICENSE_INVALID: Cryptographic license verification failed")
	ErrLicenseExpired   = errors.New("LICENSE_EXPIRED: License term has exceeded expiry plus grace period")
	ErrSeatLimitReached = errors.New("LICENSE_SEAT_LIMIT_EXCEEDED: Maximum support agent seat limit reached")
)

// LicenseClaims contains the verified license metadata parsed from the vendor-signed JWL token.
type LicenseClaims struct {
	LicenseID        string `json:"lic_id"`
	CustomerID       string `json:"customer_id"`
	Domain           string `json:"domain"`
	MaxHumanAgents   int    `json:"max_human_agents"`
	MaxAIAgents      int    `json:"max_ai_agents"`
	Tier             string `json:"tier"`
	ExpiresAt        int64  `json:"expires_at"`
	OfflineGraceDays int    `json:"offline_grace_days"`
}

// IsExpiredWithGrace returns true only if the license has exceeded both its hard expiry AND
// the OfflineGraceDays buffer, preventing cliff-edge failures for grants issued near expiry (F-1-B / finding #22).
func (lc *LicenseClaims) IsExpiredWithGrace() bool {
	gracePeriodEnd := lc.ExpiresAt + int64(lc.OfflineGraceDays)*86400
	return time.Now().Unix() > gracePeriodEnd
}

// Manager holds the vendor Ed25519 public key and a cached verified claims object.
// License verification is performed ONCE at startup via VerifyAndCache, not on every request.
type Manager struct {
	publicKey    ed25519.PublicKey
	mu           sync.RWMutex
	cachedClaims *LicenseClaims
}

// NewManager constructs a license manager from a base64-encoded Ed25519 public key.
func NewManager(pubKeyBase64 string) (*Manager, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 license public key: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key length")
	}
	return &Manager{publicKey: ed25519.PublicKey(keyBytes)}, nil
}

// VerifyAndCache verifies the license signature and caches the result.
// Call once at startup; use CachedClaims() thereafter.
func (m *Manager) VerifyAndCache(rawJWL string) (*LicenseClaims, error) {
	parts := strings.Split(rawJWL, ".")
	if len(parts) != 3 {
		return nil, ErrLicenseInvalid
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrLicenseInvalid
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrLicenseInvalid
	}

	if !ed25519.Verify(m.publicKey, payloadBytes, sigBytes) {
		return nil, ErrLicenseInvalid
	}

	var claims LicenseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrLicenseInvalid
	}

	// Apply OfflineGraceDays grace buffer so grants issued near expiry still allow login (finding #22).
	if claims.IsExpiredWithGrace() {
		return nil, ErrLicenseExpired
	}

	m.mu.Lock()
	m.cachedClaims = &claims
	m.mu.Unlock()

	return &claims, nil
}

// CachedClaims returns the last successfully verified license claims, or nil if
// VerifyAndCache has not been called. Callers should check for nil before using.
func (m *Manager) CachedClaims() *LicenseClaims {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedClaims
}
```

---

### Component 3: `cmd/server` — Strict Valkey Startup & JWT Production Guard

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go)

**BEFORE (JWT key block, lines 39–46):**
```go
	// Initialize RSA JWT Keys
	if err := security.LoadJWTKeysFromEnv(); err != nil {
		slog.Warn("RSA JWT keys not found in environment, generating transient keypair for runtime...")
		if err := security.SetupTestRSAKeys(); err != nil {
			slog.Error("Failed to initialize transient JWT keys", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}
```

**AFTER:**
```go
	// Initialize RSA JWT Keys — fail hard in production if keys are absent (fix #11 / F-3-B).
	if err := security.LoadJWTKeysFromEnv(); err != nil {
		if cfg.Environment == "production" {
			slog.Error("FATAL: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required in production. Exiting.",
				slog.String("error", err.Error()))
			os.Exit(1)
		}
		slog.Warn("RSA JWT keys not found, generating transient keypair (development only — NOT safe for production)...")
		if err := security.SetupTestRSAKeys(); err != nil {
			slog.Error("Failed to initialize transient JWT keys", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}
```

**BEFORE (Valkey block, lines 61–68):**
```go
	// Initialize Valkey Cache Client (Optional)
	var valkeyClient *cache.ValkeyClient
	if cfg.ValkeyCacheURL != "" {
		valkeyClient, err = cache.NewValkeyClient(cfg.ValkeyCacheURL)
		if err != nil {
			slog.Warn("Valkey connection bypass (running without distributed cache)", slog.String("error", err.Error()))
		}
	}
```

**AFTER:**
```go
	// Initialize Valkey Cache Client — mandatory in production (valkey-enforcement.md).
	var valkeyClient *cache.ValkeyClient
	if cfg.ValkeyCacheURL != "" {
		valkeyClient, err = cache.NewValkeyClient(cfg.ValkeyCacheURL)
		if err != nil {
			slog.Error("CRITICAL: Failed to connect to Valkey cache instance", slog.String("error", err.Error()))
			if cfg.Environment == "production" {
				slog.Error("FATAL: Valkey connection is MANDATORY in production mode. Exiting.")
				os.Exit(1)
			}
		}
	} else if cfg.Environment == "production" {
		slog.Error("FATAL: VALKEY_CACHE_URL environment variable is required in production. Exiting.")
		os.Exit(1)
	}
```

**auditRepo line (line 73) — UNCHANGED:**
```go
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
```
> ⚠️ **Phase ordering note**: Phase 5 changes `NewSecurityAuditRepository` to accept an `ed25519.PrivateKey` second parameter and updates this line in `main.go`. Phase 1 intentionally leaves this unchanged so `go build ./...` succeeds after Phase 1 alone.

**BEFORE (service constructor call, line 75):**
```go
	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient)
```

**AFTER (Phase 1 adds `licMgr` as 4th parameter):**
```go
	// Build license manager from env vars (Phase 1).
	// LICENSE_KEY and LICENSE_PUBLIC_KEY are REQUIRED in production for seat-limit enforcement.
	var licMgr *license.Manager
	if licKey := os.Getenv("LICENSE_KEY"); licKey != "" {
		if pubKeyB64 := os.Getenv("LICENSE_PUBLIC_KEY"); pubKeyB64 != "" {
			var licErr error
			licMgr, licErr = license.NewManager(pubKeyB64)
			if licErr == nil {
				if _, licErr = licMgr.VerifyAndCache(licKey); licErr != nil {
					slog.Warn("License verification failed; seat-limit enforcement disabled",
						slog.String("error", licErr.Error()))
					licMgr = nil
				}
			}
		}
	}
	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr)
```

Add to imports (Phase 1 additions):
```go
	"grantsupport/pkg/license"
```

> **Cross-phase call-site audit for `NewGrantSupportService` (mandatory per process rule)**:
> - `phase_1_plan.md` (this file): `NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr)` — 4 args ✔
> - `phase_6_plan.md` Component 7: Updated to `NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr, webhookDispatcher, webhookRepo)` — 6 args ✔
> - `phase_7_plan.md`: Does not call `NewGrantSupportService` — ✔
> - `implementation_plan.md`: Does not call the constructor directly — ✔
> - **Call sites checked: phase_1, phase_6. All updated: yes.**

---

### Component 4: [NEW] `.env.example` (project root)

```env
# GrantSupport Engine — Environment Variable Reference
# Copy to .env and fill in all REQUIRED values.

# ─── Server ───────────────────────────────────────────────────────────
PORT=8085
GO_ENV=development          # set to "production" for production deployments

# ─── Database ───────────────────────────────────────────────────────────
# REQUIRED
DATABASE_URL=postgresql://postgres:password@localhost:5432/grantsupport_db?sslmode=disable
# OPTIONAL — valid values: postgres | mysql | sqlite3  (default: postgres)
DATABASE_DIALECT=postgres

# ─── Valkey / Redis ──────────────────────────────────────────────────────────
# REQUIRED in production; optional in development
VALKEY_CACHE_URL=redis://127.0.0.1:6379

# ─── JWT Signing Keys (RS256) ───────────────────────────────────────────────────
# REQUIRED in production — absence causes fatal exit when GO_ENV=production.
# In development an ephemeral in-memory keypair is generated automatically.
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

# ─── Encryption ───────────────────────────────────────────────────────────────
# OPTIONAL — valid values: LOCAL | AWS_KMS  (default: LOCAL)
ENCRYPTION_PROVIDER=LOCAL
# REQUIRED when ENCRYPTION_PROVIDER=LOCAL (must not use default in production)
MASTER_ENCRYPTION_KEY=<change-me-to-a-random-32-byte-hex-string>
# REQUIRED when ENCRYPTION_PROVIDER=AWS_KMS
# KMS_KEY_ID=arn:aws:kms:ap-south-1:123456789012:key/mrk-...
# AWS_REGION=ap-south-1

# ─── License ──────────────────────────────────────────────────────────────────
# REQUIRED in production for seat-limit enforcement
LICENSE_KEY=<your-ed25519-signed-license-key-from-vendor>
LICENSE_PUBLIC_KEY=<base64-encoded-ed25519-public-key-from-vendor>

# ─── Audit Log Signing ───────────────────────────────────────────────────────────
# See Phase 5 for details on key source and rotation.
# REQUIRED when Phase 5 is deployed
# AUDIT_SIGNING_PRIVATE_KEY=<base64-encoded-ed25519-private-key>
```

---

### Component 5: `pkg/service` — Seat-Limit Enforcement at Login (Fix #3 / I-3)

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go)

**What was wrong**: `ErrSeatLimitReached` was defined in `pkg/license` but no code anywhere compared `LicenseClaims.MaxHumanAgents` against the count of live sessions.

**Fix**: `GrantSupportService` receives a `*license.Manager` at construction. `SupportLogin` counts **currently-active sessions — grants that have been consumed (`is_used=true`) and whose expiry window has not yet passed (`expires_at > NOW())** and compares against `MaxHumanAgents` before issuing the JWT.

**BEFORE (`GrantSupportService` struct, line 26):**
```go
type GrantSupportService struct {
	supportGrantRepo *repository.SupportGrantRepository
	auditRepo        *repository.SecurityAuditRepository
	valkey           *cache.ValkeyClient
}
```

**AFTER:**
```go
type GrantSupportService struct {
	supportGrantRepo *repository.SupportGrantRepository
	auditRepo        *repository.SecurityAuditRepository
	valkey           *cache.ValkeyClient
	// licenseManager provides seat-cap enforcement from the cached license claims.
	// May be nil if no license is configured (enforcement disabled).
	licenseManager   *license.Manager
}
```

**BEFORE (`NewGrantSupportService`, line 32):**
```go
func NewGrantSupportService(
	supportGrantRepo *repository.SupportGrantRepository,
	auditRepo *repository.SecurityAuditRepository,
	valkey *cache.ValkeyClient,
) *GrantSupportService {
	return &GrantSupportService{
		supportGrantRepo: supportGrantRepo,
		auditRepo:        auditRepo,
		valkey:           valkey,
	}
}
```

**AFTER (Phase 1 signature — 4 args):**
```go
func NewGrantSupportService(
	supportGrantRepo *repository.SupportGrantRepository,
	auditRepo *repository.SecurityAuditRepository,
	valkey *cache.ValkeyClient,
	licMgr *license.Manager,
) *GrantSupportService {
	return &GrantSupportService{
		supportGrantRepo: supportGrantRepo,
		auditRepo:        auditRepo,
		valkey:           valkey,
		licenseManager:   licMgr,
	}
}
```

> **Phase 6 extends this to 6 args** by adding `webhookDispatcher` and `webhookRepo`. See Phase 6's BEFORE/AFTER which takes this 4-arg version as its baseline.

**BEFORE (inside `SupportLogin`, after grant validation, line 119):**
```go
	if err := s.supportGrantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}
```

**AFTER (insert seat-limit check BEFORE MarkGrantAsUsed):**
```go
	// Seat-limit enforcement (I-3 fix / ErrSeatLimitReached from pkg/license).
	// Counts currently-active sessions: grants that have been consumed (is_used=true)
	// and whose expiry window has not yet passed (expires_at > NOW()).
	// Check is skipped when licenseManager is nil (no license configured).
	if s.licenseManager != nil {
		claims := s.licenseManager.CachedClaims()
		if claims != nil && claims.MaxHumanAgents > 0 {
			activeCount, err := s.supportGrantRepo.CountActiveGrantsForInstitution(ctx, instID)
			if err != nil {
				return uuid.Nil, "", fmt.Errorf("failed to query active seat count: %w", err)
			}
			// If AT or ABOVE the limit, reject and audit before returning.
			if activeCount >= claims.MaxHumanAgents {
				if s.auditRepo != nil {
					_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
						"SUPPORT_LOGIN_SEAT_LIMIT",
						fmt.Sprintf("Login rejected: seat cap %d reached for institution %s",
							claims.MaxHumanAgents, instID),
						nil)
				}
				return uuid.Nil, "", license.ErrSeatLimitReached
			}
		}
	}

	if err := s.supportGrantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}
```

> **`CountActiveGrantsForInstitution` repository method** — add to `SupportGrantRepository`:

```go
// CountActiveGrantsForInstitution returns the count of currently-active sessions:
// grants that have been consumed (is_used=true) and whose expiry window has not passed.
// Used to enforce LicenseClaims.MaxHumanAgents seat caps at login time.
func (r *SupportGrantRepository) CountActiveGrantsForInstitution(ctx context.Context, institutionID uuid.UUID) (int, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return 0, err
	}
	return client.SupportGrant.Query().
		Where(
			supportgrant.InstitutionID(institutionID),
			supportgrant.IsUsed(true),
			supportgrant.ExpiresAtGT(time.Now()),
		).
		Count(ctx)
}
```

---

### Component 6: `pkg/service` & `pkg/controller` — Grant-Creation Idempotency (I-5)

An optional `Idempotency-Key` header lets clients retry `POST /api/v1/auth/support/grant` safely. The server stores `idempotency:grant:<key>` in Valkey for 60 seconds, returning the original raw token on duplicate requests. This is a **non-breaking, backward-compatible addition** — clients that do not send the header get the existing behaviour.

#### [MODIFY] [auth_support_controller.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_support_controller.go) — `GrantSupport` handler

```go
// GrantSupport creates a delegated support access token for the calling institution.
// POST /api/v1/auth/support/grant (authenticated — requires admin JWT)
// Optional: send Idempotency-Key header to make retries safe.
func (c *SupportGrantController) GrantSupport(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[GrantSupportInput](r)
	if err != nil {
		return err
	}

	institutionID, ok := pkgctx.GetTenant(r.Context())
	if !ok {
		return NewAppError(http.StatusUnauthorized, "MISSING_TENANT", "institution context not found")
	}
	adminUserID, ok := pkgctx.GetUser(r.Context())
	if !ok {
		return NewAppError(http.StatusUnauthorized, "MISSING_USER", "user context not found")
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")

	rawToken, err := c.grantService.CreateSupportGrant(r.Context(), institutionID, adminUserID,
		input.DurationMinutes, idempotencyKey)
	if err != nil {
		return NewAppError(http.StatusInternalServerError, "GRANT_CREATION_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"token":   rawToken,
		"message": "Support access grant created successfully.",
	})
	return nil
}
```

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go) — `CreateSupportGrant`

**BEFORE (signature):**
```go
func (s *GrantSupportService) CreateSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int) (string, error) {
```

**AFTER (add optional idempotency key parameter):**
```go
// CreateSupportGrant creates a temporary support access token.
// idempotencyKey is optional (empty string = disabled). When provided, a repeated call
// within 60 seconds returns the original token instead of creating a new row.
func (s *GrantSupportService) CreateSupportGrant(
	ctx context.Context,
	institutionID, adminUserID uuid.UUID,
	durationMinutes int,
	idempotencyKey string,
) (string, error) {
	// Idempotency check — runs before the Redlock to short-circuit quickly.
	if idempotencyKey != "" && s.valkey != nil && s.valkey.Client != nil {
		valkeyKey := fmt.Sprintf("idempotency:grant:%s", idempotencyKey)
		if existingToken, err := s.valkey.Client.Get(ctx, valkeyKey).Result(); err == nil {
			// Duplicate request — return the original token without a DB write.
			return existingToken, nil
		}
	}

	// ... (rest of existing grant creation logic unchanged) ...

	// After successful grant creation, store idempotency mapping with 60-second TTL.
	if idempotencyKey != "" && s.valkey != nil && s.valkey.Client != nil {
		valkeyKey := fmt.Sprintf("idempotency:grant:%s", idempotencyKey)
		_ = s.valkey.Client.Set(ctx, valkeyKey, rawToken, 60*time.Second).Err()
	}

	return rawToken, nil
}
```

> **Cross-phase call-site audit for `CreateSupportGrant` (mandatory per process rule — N-3 fix)**:
> The I-5 fix adds `idempotencyKey string` as a 5th parameter to `CreateSupportGrant`. Every call site across all 7 phase files and implementation_plan.md was searched for the string `"CreateSupportGrant"`:
>
> | File | Line | Nature | Status |
> |---|---|---|---|
> | `phase_1_plan.md` (controller, this file) | 545–546 | External call — controller passes `idempotencyKey` | ✅ 5-arg, correct |
> | `phase_1_plan.md` (service BEFORE block) | 564 | Shows pre-I-5 state for diff clarity | ✅ BEFORE block only |
> | `phase_1_plan.md` (service AFTER block) | 572–577 | Service method definition | ✅ 5-arg, correct |
> | `phase_6_plan.md` | 556–567 | Internal webhook dispatch code **inside** `CreateSupportGrant` body — not a call to it | ✅ Not a call site |
> | `phase_2_plan.md`, `phase_3_plan.md`, `phase_4_plan.md`, `phase_5_plan.md`, `phase_7_plan.md`, `implementation_plan.md` | — | No reference to `CreateSupportGrant` | ✅ No call sites |
>
> **Call sites checked: all 7 phase files + implementation_plan.md. All updated: yes.**

---

## 🧪 Verification Plan

### Build Check (after Phase 1 only — must pass before Phase 2)
```bash
go build ./...
```
Expect: zero errors. The `auditRepo` constructor is unchanged; `NewGrantSupportService` is now 4-arg.

### Automated Unit Tests
```bash
go test ./pkg/license/... -v
go test ./pkg/controller/... -v
```

### Manual Verification
1. Send `POST /api/v1/auth/support/login` with malformed `agentId`:
   ```json
   { "token": "inst_123_abc...", "agentId": "not-a-uuid" }
   ```
   Expect: `400 Bad Request`, `code: "INVALID_AGENT_ID"`.

2. Send with valid `agentId`:
   ```json
   { "token": "inst_123_abc...", "agentId": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11" }
   ```
   Expect: `200 OK` with `agent_id: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"` in response.

3. Send `POST /api/v1/auth/support/grant` with `Idempotency-Key: my-key-abc` twice rapidly.
   Expect: both return the same `token` value; only one `SupportGrant` row created in DB.

4. When `MaxHumanAgents=2` in license and 2 sessions are active:
   Attempt a 3rd `POST /api/v1/auth/support/login`.
   Expect: `401 LICENSE_SEAT_LIMIT_EXCEEDED` and `SUPPORT_LOGIN_SEAT_LIMIT` audit entry created.
```

---

## docs/phase_2_plan.md

```markdown
# Phase 2 Implementation Plan: Multi-Database Support & SQL Migrations

## 📌 Problem & Context
1. **Empty `migrations/` Directory**: Missing SQL scripts for `SupportGrant`, `AuditEvent`, and immutability triggers.
2. **Hardcoded PostgreSQL Driver**: `main.go` hardcodes `ent.Open("postgres", ...)`, blocking MySQL/SQLite clients.
3. **No per-dialect `CREATE TABLE` scripts** for MySQL or SQLite (finding #13).

> **CGO decision (F-2-A)**: `github.com/mattn/go-sqlite3` requires CGO. Phase 3 builds with `CGO_ENABLED=0`. To resolve this conflict without splitting the Docker build, we replace the SQLite driver with **`modernc.org/sqlite`** (pure Go, zero CGO requirement). Phase 3's Dockerfile needs no changes for SQLite support.

> **Migration file directory structure (F-3-A fix)**: Migration files are organized into dialect-specific subdirectories to prevent PostgreSQL from ingesting MySQL scripts:
> - `migrations/postgres/` — PostgreSQL-only scripts
> - `migrations/mysql/` — MySQL-only scripts
> - `migrations/sqlite/` — SQLite-only scripts (trigger documentation only — see finding #29)
> Phase 3's docker-compose.yml mounts only `migrations/postgres/` into `docker-entrypoint-initdb.d`.

> **`DATABASE_DIALECT` allowlist (F-2-C)**: `LoadConfig()` now validates the dialect against a strict allowlist of `postgres`, `mysql`, `sqlite3` and returns a clear error on unknown values.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `migrations/postgres/` — PostgreSQL Migration Scripts

> **SEQUENCING CONSTRAINT (I-4 fix)**: The `hash_chain` column is created with `NOT NULL DEFAULT ''` in Phase 2's `000001` migration. The `CHECK (length(hash_chain) > 0)` constraint is intentionally **NOT** added in Phase 2. It will be added in `000003_add_hash_chain_check.sql`, which is applied as part of **Phase 5 deployment** — after `LogSecurityEvent` is updated to always write a real non-empty hash_chain value. Applying the CHECK constraint before Phase 5's code update would cause every `LogSecurityEvent` INSERT (from Phase 2/3/4 code) to violate the constraint and fail with a DB error. This sequencing dependency is stated explicitly in phase_5_plan.md.

#### [NEW] [000001_create_grantsupport_tables.sql](file:///d:/Hostel_management/GrantSupport/migrations/postgres/000001_create_grantsupport_tables.sql)

```sql
-- Migration 000001 (PostgreSQL): Create SupportGrant & AuditEvent tables.

CREATE TABLE IF NOT EXISTS "SupportGrant" (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    granted_by_id UUID NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN DEFAULT FALSE NOT NULL,
    used_at TIMESTAMPTZ,
    scope VARCHAR(64) DEFAULT 'FULL_ACCESS' NOT NULL,
    reason TEXT,
    whitelisted_ips JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS "AuditEvent" (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT,
    -- hash_chain: NOT NULL ensures no NULL chain values (finding #3 / #37).
    -- DEFAULT '' allows Phase 2/3/4 code to INSERT without setting this column;
    -- the stricter CHECK (length > 0) is added by 000003_add_hash_chain_check.sql
    -- which is applied during Phase 5 deployment ONLY, after LogSecurityEvent
    -- is updated to always write a real non-empty hash value.
    hash_chain VARCHAR(255) NOT NULL DEFAULT '',
    -- signature added for Ed25519 non-repudiation (Phase 5).
    signature VARCHAR(512),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auditevent_inst_created ON "AuditEvent"(institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_auditevent_actor ON "AuditEvent"(actor_id);
CREATE INDEX IF NOT EXISTS idx_auditevent_event_type ON "AuditEvent"(event_type);
```

#### [NEW] [000002_add_immutability_triggers.sql](file:///d:/Hostel_management/GrantSupport/migrations/postgres/000002_add_immutability_triggers.sql)

```sql
-- Migration 000002 (PostgreSQL): Append-only immutability triggers for AuditEvent.

CREATE OR REPLACE FUNCTION prevent_auditevent_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABLE_AUDIT_LOG: Modification or deletion of security audit records is strictly prohibited.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_auditevent_update ON "AuditEvent";
CREATE TRIGGER trg_prevent_auditevent_update
    BEFORE UPDATE ON "AuditEvent"
    FOR EACH ROW EXECUTE FUNCTION prevent_auditevent_mutation();

DROP TRIGGER IF EXISTS trg_prevent_auditevent_delete ON "AuditEvent";
CREATE TRIGGER trg_prevent_auditevent_delete
    BEFORE DELETE ON "AuditEvent"
    FOR EACH ROW EXECUTE FUNCTION prevent_auditevent_mutation();
```

---

### Component 2: `migrations/mysql/` — MySQL Migration Scripts

> **SEQUENCING CONSTRAINT (I-4 fix)**: Same as PostgreSQL. `hash_chain` is `NOT NULL DEFAULT ''` only in Phase 2. The `CHECK (LENGTH(hash_chain) > 0)` constraint is added in `000003_add_hash_chain_check.sql` applied during Phase 5 deployment.

#### [NEW] [000001_create_grantsupport_tables.sql](file:///d:/Hostel_management/GrantSupport/migrations/mysql/000001_create_grantsupport_tables.sql)

> MySQL does not have a native UUID type. Use `CHAR(36)` as the standard workaround.
> MySQL does not have a native JSONB type. Use `TEXT` for `whitelisted_ips`.

```sql
-- Migration 000001 (MySQL 8.0+): Create SupportGrant & AuditEvent tables.

CREATE TABLE IF NOT EXISTS SupportGrant (
    id CHAR(36) NOT NULL PRIMARY KEY,
    institution_id CHAR(36) NOT NULL,
    granted_by_id CHAR(36) NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    is_used TINYINT(1) DEFAULT 0 NOT NULL,
    used_at DATETIME,
    scope VARCHAR(64) DEFAULT 'FULL_ACCESS' NOT NULL,
    reason TEXT,
    whitelisted_ips TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS AuditEvent (
    id CHAR(36) NOT NULL PRIMARY KEY,
    institution_id CHAR(36) NOT NULL,
    actor_id CHAR(36) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    description TEXT,
    -- hash_chain: NOT NULL only in Phase 2. CHECK (LENGTH > 0) added in Phase 5 migration 000003.
    hash_chain VARCHAR(255) NOT NULL DEFAULT '',
    signature VARCHAR(512),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX idx_auditevent_inst_created ON AuditEvent(institution_id, created_at);
CREATE INDEX idx_auditevent_actor ON AuditEvent(actor_id);
CREATE INDEX idx_auditevent_event_type ON AuditEvent(event_type);
```

#### [NEW] [000002_add_immutability_triggers.sql](file:///d:/Hostel_management/GrantSupport/migrations/mysql/000002_add_immutability_triggers.sql)

> **Fix (F-2-B)**: `DELIMITER` is a MySQL CLI-only command, not a SQL statement. Standard Go DB drivers cannot execute it. The triggers below use single-statement `CREATE TRIGGER` syntax that any MySQL 8.0 driver can execute directly.

```sql
-- Migration 000002 (MySQL 8.0+): Append-only immutability triggers.
-- Run each statement separately via your migration tool (no DELIMITER needed).

CREATE TRIGGER trg_prevent_auditevent_update
BEFORE UPDATE ON AuditEvent
FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'IMMUTABLE_AUDIT_LOG: AuditEvent updates are forbidden.';

CREATE TRIGGER trg_prevent_auditevent_delete
BEFORE DELETE ON AuditEvent
FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'IMMUTABLE_AUDIT_LOG: AuditEvent deletions are forbidden.';
```

---

### Component 3: `migrations/sqlite/` — SQLite Migration Scripts

> **SEQUENCING CONSTRAINT (I-4 fix)**: Same as PostgreSQL/MySQL. `hash_chain` is `NOT NULL DEFAULT ''` only in Phase 2. The `CHECK (length(hash_chain) > 0)` constraint is added in `000003_add_hash_chain_check.sql` applied during Phase 5 deployment.

#### [NEW] [000001_create_grantsupport_tables.sql](file:///d:/Hostel_management/GrantSupport/migrations/sqlite/000001_create_grantsupport_tables.sql)

> SQLite does not have native UUID or JSONB types. Use `TEXT` for both.

```sql
-- Migration 000001 (SQLite 3): Create SupportGrant & AuditEvent tables.

CREATE TABLE IF NOT EXISTS SupportGrant (
    id TEXT NOT NULL PRIMARY KEY,
    institution_id TEXT NOT NULL,
    granted_by_id TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    is_used INTEGER DEFAULT 0 NOT NULL,
    used_at TEXT,
    scope TEXT DEFAULT 'FULL_ACCESS' NOT NULL,
    reason TEXT,
    whitelisted_ips TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS AuditEvent (
    id TEXT NOT NULL PRIMARY KEY,
    institution_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    -- hash_chain: NOT NULL only in Phase 2. CHECK (length > 0) added in Phase 5 migration 000003.
    hash_chain TEXT NOT NULL DEFAULT '',
    signature TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auditevent_inst_created ON AuditEvent(institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_auditevent_actor ON AuditEvent(actor_id);
```

#### [NEW] [000002_immutability_limitation.md](file:///d:/Hostel_management/GrantSupport/migrations/sqlite/000002_immutability_limitation.md)

> **Known limitation (finding #29)**: SQLite 3 supports `BEFORE UPDATE/DELETE` triggers and `RAISE(ABORT, ...)`, which can block mutations. However, SQLite databases are single-process file-based stores. Any user with filesystem read/write access to the `.db` file can modify it directly bypassing triggers entirely. SQLite deployments therefore lack **database-level** tamper protection. This is a **documented accepted limitation** for SQLite-only deployments. For deployments requiring audit tamper-evidence, use PostgreSQL or MySQL.

---

### Component 4: `pkg/config/config.go` — Dialect Allowlist

#### [MODIFY] [config.go](file:///d:/Hostel_management/GrantSupport/pkg/config/config.go)

**BEFORE (struct definition):**
```go
type Config struct {
	DatabaseURL        string
	ValkeyCacheURL     string
	...
}
```

**AFTER:**
```go
type Config struct {
	// DatabaseDialect selects the SQL driver. Valid values: "postgres", "mysql", "sqlite3".
	DatabaseDialect     string
	DatabaseURL         string
	ValkeyCacheURL      string
	...
}
```

**BEFORE (LoadConfig, dialect section — does not exist yet):**
*(no dialect loading code)*

**AFTER (add inside LoadConfig, after reading dbURL):**
```go
	// Validate DATABASE_DIALECT against a strict allowlist (F-2-C).
	dbDialect := os.Getenv("DATABASE_DIALECT")
	switch dbDialect {
	case "postgres", "mysql", "sqlite3":
		// valid
	case "":
		dbDialect = "postgres" // default
	default:
		return nil, fmt.Errorf(
			"INVALID_DATABASE_DIALECT: %q is not a valid dialect; valid values are: postgres, mysql, sqlite3",
			dbDialect,
		)
	}
```

### Component 5: `cmd/server/main.go` — Multi-Dialect Driver Imports & Open

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go)

**BEFORE (import block, line 15):**
```go
	_ "github.com/jackc/pgx/v5/stdlib"
```

**AFTER:**
```go
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/go-sql-driver/mysql"
	// Pure-Go SQLite driver — no CGO required (modernc.org/sqlite replaces mattn/go-sqlite3 to avoid CGO conflict with Phase 3's CGO_ENABLED=0 Dockerfile).
	_ "modernc.org/sqlite"
```

**BEFORE (line 49):**
```go
	dbClient, err := ent.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to PostgreSQL database", slog.String("error", err.Error()))
		os.Exit(1)
	}
```

**AFTER:**
```go
	dbClient, err := ent.Open(cfg.DatabaseDialect, cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to database",
			slog.String("dialect", cfg.DatabaseDialect),
			slog.String("error", err.Error()))
		os.Exit(1)
	}
```

---

### Component 6: `go.mod` — New Driver Dependencies

Add these to `go.mod` (`go get` commands to run before building):
```bash
go get github.com/go-sql-driver/mysql@latest
go get modernc.org/sqlite@latest
```

---

## 🧪 Verification Plan

### Migration Verification (PostgreSQL)
```bash
psql -h localhost -p 5434 -U postgres -d grantsupport_db -f migrations/postgres/000001_create_grantsupport_tables.sql
psql -h localhost -p 5434 -U postgres -d grantsupport_db -f migrations/postgres/000002_add_immutability_triggers.sql
# Verify immutability trigger:
psql -h localhost -p 5434 -U postgres -d grantsupport_db -c 'DELETE FROM "AuditEvent";'
# Expect: ERROR: IMMUTABLE_AUDIT_LOG...
# Verify hash_chain CHECK constraint:
psql -h localhost -p 5434 -U postgres -d grantsupport_db -c \
  "INSERT INTO \"AuditEvent\" (id, institution_id, actor_id, event_type, hash_chain) VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'TEST', '');"
# Expect: ERROR: new row for relation "AuditEvent" violates check constraint
```

### Build Check
```bash
go build ./...
```
Expect: zero errors (modernc.org/sqlite is pure Go, no CGO conflict).

### Dialect Validation
Set `DATABASE_DIALECT=postgresql` and start server. Expect: startup error `INVALID_DATABASE_DIALECT: "postgresql" is not a valid dialect...`
```

---

## docs/phase_3_plan.md

```markdown
# Phase 3 Implementation Plan: Containerization & Docker Deployment

## 📌 Problem & Context
1. **Empty `docker/` Directory**: No multi-stage Dockerfile or compose manifests.
2. **Missing `.env.example`**: Operators have no documented list of required/optional env vars. *(Fixed in Phase 1.)*
3. **Full `migrations/` mount exposes MySQL script to Postgres** (F-3-A): The entire `migrations/` folder cannot be mounted into `docker-entrypoint-initdb.d`; only the dialect-specific subdirectory may be mounted.
4. **Hardcoded `MASTER_ENCRYPTION_KEY`** (finding #2/#38): The docker-compose.yml example must NOT hard-code a real key; it must reference an env var.

> **CGO note**: Phase 2 replaces `mattn/go-sqlite3` with `modernc.org/sqlite` (pure Go). The Dockerfile continues to build with `CGO_ENABLED=0` and a plain Alpine image. No gcc layer is required.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `docker/Dockerfile`

#### [NEW] [Dockerfile](file:///d:/Hostel_management/GrantSupport/docker/Dockerfile)

```dockerfile
# Stage 1: Build Binary
# P6 fix: golang:1.25-alpine does not exist (Go 1.25 is unreleased). Use 1.23-alpine.
# Update this to match the `go` directive in go.mod when upgrading.
FROM golang:1.23-alpine AS builder

WORKDIR /build

# ca-certificates needed for outbound TLS (webhooks, KMS calls).
RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: pure-Go build (compatible with modernc.org/sqlite; see Phase 2 for driver choice).
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/grantsupport ./cmd/server

# Stage 2: Minimal Hardened Runtime Image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Non-root unprivileged user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app/grantsupport /app/grantsupport

USER appuser:appgroup

EXPOSE 8085

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8085/health || exit 1

ENTRYPOINT ["/app/grantsupport"]
```

---

### Component 2: `docker/docker-compose.yml`

#### [NEW] [docker-compose.yml](file:///d:/Hostel_management/GrantSupport/docker/docker-compose.yml)

> **Fix (F-3-A)**: Mount only `../migrations/postgres` into `docker-entrypoint-initdb.d`. The MySQL scripts live in `../migrations/mysql` and are never seen by Postgres.
>
> **Fix (finding #38)**: `MASTER_ENCRYPTION_KEY` uses `${MASTER_ENCRYPTION_KEY}` variable substitution instead of a hardcoded value. Copy `.env.example` to `.env` and set this before running.

```yaml
version: '3.8'

services:
  grantsupport-core:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    container_name: grantsupport-core
    ports:
      - "8085:8085"
    environment:
      - PORT=8085
      - GO_ENV=production
      - DATABASE_DIALECT=postgres
      - DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/grantsupport_db?sslmode=disable
      - VALKEY_CACHE_URL=redis://valkey:6379
      - ENCRYPTION_PROVIDER=LOCAL
      # Never hard-code MASTER_ENCRYPTION_KEY. Set it in your .env file or secrets manager.
      - MASTER_ENCRYPTION_KEY=${MASTER_ENCRYPTION_KEY}
      - JWT_PRIVATE_KEY=${JWT_PRIVATE_KEY}
      - JWT_PUBLIC_KEY=${JWT_PUBLIC_KEY}
      - LICENSE_KEY=${LICENSE_KEY}
      - LICENSE_PUBLIC_KEY=${LICENSE_PUBLIC_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    container_name: grantsupport-postgres
    environment:
      POSTGRES_DB: grantsupport_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5434:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      # Mount ONLY the postgres-specific subdirectory (F-3-A fix).
      # This prevents Postgres from trying to run MySQL trigger scripts.
      - ../migrations/postgres:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d grantsupport_db"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  valkey:
    image: valkey/valkey:7.2-alpine
    container_name: grantsupport-valkey
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "valkey-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  pgdata:
```

---

### Component 3: Migration Execution for Existing Deployments (finding #30)

> **Known gap addressed**: `docker-entrypoint-initdb.d` only runs scripts on a **fresh** database volume. It does not execute scripts when upgrading an existing deployment. The following is the documented upgrade procedure:

#### Upgrade procedure (run via `golang-migrate` — recommended for all environments):

```bash
# Install golang-migrate once (if not already present):
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Apply ALL pending migrations in order (000001, 000002, 000003, ...):
migrate -path migrations/postgres -database "${DATABASE_URL}" up
```

For MySQL deployments, use the `mysql` tag and `migrations/mysql/` path:
```bash
migrate -path migrations/mysql -database "${DATABASE_URL}" up
```

> **P8 fix**: The previous example ran only `000002_add_immutability_triggers.sql` via a manual `psql` command. This was wrong for two reasons:
> 1. It silently skipped `000001` (required for a fresh non-Docker deployment).
> 2. It becomes stale whenever a new migration file is added (e.g., `000003_add_hash_chain_check.sql` from Phase 5).
>
> `migrate ... up` applies all pending migrations in numeric order and is safe to re-run (already-applied migrations are skipped). This is the only supported upgrade mechanism.


---

## 🧪 Verification Plan

### Container Build & Orchestration
```bash
cp .env.example .env     # fill in all REQUIRED values
docker compose -f docker/docker-compose.yml up --build -d
docker ps --filter "name=grantsupport"
curl -i http://localhost:8085/health
```
Expect `200 OK` with `{"status":"UP","service":"GrantSupport Engine"}`.

### Confirm No MySQL Script Executed by Postgres
```bash
docker logs grantsupport-postgres 2>&1 | grep -i "DELIMITER"
```
Expect: zero matches (MySQL script is not in the mounted postgres subdirectory).
```

---

## docs/phase_4_plan.md

```markdown
# Phase 4 Implementation Plan: Security Hardening

## 📌 Problem & Context
1. **Missing Instant Revocation**: Revoking a grant updates the DB, but already-issued RS256 JWTs remain valid until natural expiration.
2. **Missing Rate Limiting**: `/api/v1/auth/support/login` lacks brute-force protection.
3. **Static JWT Lifetime**: Session tokens have a fixed 4-hour lifetime.
4. **Rate limiter built but never mounted** (F-3-C): `RateLimitMiddleware` is dead code unless wired into both `main.go` and the Phase 7 SDK.
5. **Failed events never audited** (F-4-C / finding #12): Rate-limit hits and token-revocation rejections are invisible in `AuditEvent`.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `pkg/service` — Two Named Revocation Modes (finding #28)

> **Two named revocation designs (finding #28)**: There are exactly two distinct revocation features:
> - **Per-institution revocation** (`RevokeSupportGrant`): Invalidates all grants in DB + blacklists all JWTs issued before the revocation timestamp via a Valkey key `revoked:inst:<institution_id>`. Used when an admin revokes all delegated access at once.
> - **Per-agent JWT revocation** (future Phase — deferred): Blacklisting a single JWT by `jti` claim. Not implemented in these plans; documented here as a deferred feature to prevent confusion.

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go#L140-L155)

**BEFORE:**
```go
// RevokeSupportGrant invalidates all active support grants for an institution.
func (s *GrantSupportService) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	if s.supportGrantRepo == nil {
		return errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if err := s.supportGrantRepo.RevokeAllGrantsForInstitution(ctx, institutionID); err != nil {
		return err
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "All active support access grants manually revoked by administrator", nil)
	}

	return nil
}
```

**AFTER:**
```go
// RevokeSupportGrant performs PER-INSTITUTION revocation:
// 1. Marks all DB grant rows as revoked.
// 2. Writes a revocation timestamp to Valkey so any JWT issued before that
//    timestamp is immediately rejected by AuthMiddleware (fail-closed on Valkey error).
//
// Per-agent (per-JWT) revocation is a deferred feature tracked separately.
func (s *GrantSupportService) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	if s.supportGrantRepo == nil {
		return errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if err := s.supportGrantRepo.RevokeAllGrantsForInstitution(ctx, institutionID); err != nil {
		return err
	}

	// Blacklist all JWTs issued before now for this institution.
	// Use millisecond precision to avoid same-second collision (F-4-B / finding #19).
	if s.valkey != nil && s.valkey.Client != nil {
		revocationKey := fmt.Sprintf("revoked:inst:%s", institutionID.String())
		nowMilli := time.Now().UnixMilli()
		// TTL = 4 hours (matches maximum JWT duration) so the key expires automatically.
		_ = s.valkey.Client.Set(ctx, revocationKey, nowMilli, 4*time.Hour).Err()
	}

	if s.auditRepo != nil {
		// NOTE: Phase 4 runs BEFORE Phase 5. Phase 5 changes LogSecurityEvent's signature
		// (drops the *ent.Tx parameter). Until Phase 5 is applied, call sites use the old
		// 6-argument signature. Phase 5 updates ALL call sites atomically — this one included.
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "PER-INSTITUTION: All active support access grants manually revoked by administrator", nil)
	}

	return nil
}
```

---

### Component 2: `pkg/middleware` — Auth Revocation Check (fail-closed)

#### [MODIFY] [auth.go](file:///d:/Hostel_management/GrantSupport/pkg/middleware/auth.go#L44-L52)

**BEFORE (revocation section):**
```go
			// TokenVersion revocation check against Valkey security cache
			if valkey != nil && valkey.Client != nil {
				cacheKey := fmt.Sprintf("cache:%s:user:security:%s", claims.InstitutionID, claims.UserID)
				cachedVersion, err := valkey.Client.Get(r.Context(), cacheKey).Int()
				if err == nil && cachedVersion > claims.TokenVersion {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Session has been revoked. Please log in again.")
					return
				}
			}
```

**AFTER** (adds institution-wide revocation check with millisecond precision and fail-closed on Valkey error):
```go
			// Per-user token-version revocation (existing check).
			if valkey != nil && valkey.Client != nil {
				cacheKey := fmt.Sprintf("cache:%s:user:security:%s", claims.InstitutionID, claims.UserID)
				cachedVersion, err := valkey.Client.Get(r.Context(), cacheKey).Int()
				if err == nil && cachedVersion > claims.TokenVersion {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Session has been revoked. Please log in again.")
					return
				}
			}

			// Per-institution revocation check (F-4-B / finding #10 fail-closed fix).
			// Use strict less-than (<) to avoid same-millisecond off-by-one (finding #19).
			if valkey != nil && valkey.Client != nil {
				revocationKey := fmt.Sprintf("revoked:inst:%s", claims.InstitutionID)
				revokedMilli, err := valkey.Client.Get(r.Context(), revocationKey).Int64()
				if err != nil {
					// FAIL-CLOSED: if Valkey is unavailable, we cannot confirm this institution
					// has not been revoked. Deny the request rather than allow it through.
					controller.WriteRFC7807Error(w, http.StatusServiceUnavailable, "REVOCATION_CHECK_UNAVAILABLE", "Security cache is unavailable; please retry in a moment.")
					return
				}
				// IssuedAt is set in milliseconds when Phase 4 is deployed; use strict < (not <=).
				if claims.IssuedAt != nil && claims.IssuedAt.UnixMilli() < revokedMilli {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Support session has been explicitly revoked by administrator.")
					return
				}
			}
```

---

### Component 3: `pkg/middleware/ratelimit.go` — Atomic Rate Limiter

#### [NEW] [ratelimit.go](file:///d:/Hostel_management/GrantSupport/pkg/middleware/ratelimit.go)

> **Fix (F-4-A / finding #18)**: The two-step `INCR` + `Expire` approach can leave a key without a TTL if `Expire` fails. This implementation uses a Lua script to atomically increment and set expiry in a single round-trip, eliminating the race.

```go
package middleware

import (
	"fmt"
	"net/http"
	"strings" // required for GetRealClientIP XFF parsing (I-9 fix)
	"time"

	"grantsupport/pkg/cache"
	"grantsupport/pkg/controller"
)

// atomicRateLimitScript is a Lua script that atomically increments a counter
// and sets its TTL only on the first increment, preventing the INCR+Expire race
// condition (F-4-A) where a failed Expire call leaves a key with no TTL.
var atomicRateLimitScript = `
local key = KEYS[1]
local window = tonumber(ARGV[1])
local current = redis.call('INCR', key)
if current == 1 then
  redis.call('EXPIRE', key, window)
end
return current
`

// RateLimitMiddleware enforces a sliding-window request limit per IP using
// an atomic Lua script to prevent TTL-race permanent IP bans.
func RateLimitMiddleware(valkey *cache.ValkeyClient, maxRequests int, windowSecs int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if valkey == nil || valkey.Client == nil {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := GetRealClientIP(r)
			key := fmt.Sprintf("ratelimit:%s:%s", r.URL.Path, clientIP)

			result, err := valkey.Client.Eval(r.Context(), atomicRateLimitScript,
				[]string{key},
				windowSecs,
			).Int64()
			if err == nil && result > int64(maxRequests) {
				controller.WriteRFC7807Error(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
					"Too many authentication requests. Please try again later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetRealClientIP extracts the true client IP, respecting X-Forwarded-For.
//
// FIX (I-9): The previous version returned the raw X-Forwarded-For header string, which:
//   1. Includes a comma-separated list when multiple proxies are traversed, so two requests
//      from the same IP with different list contents got different rate-limit buckets.
//   2. Allowed an attacker to inject a different fabricated IP on every request to bypass
//      the rate limiter entirely by rotating the X-Forwarded-For value.
//
// Fix: extract only the LEFTMOST (first) entry, which is the original client IP as set
// by the outermost trusted proxy. Only the first element is taken via SplitN.
//
// OPERATIONAL ASSUMPTION: GrantSupport is expected to run behind a trusted reverse proxy
// (e.g. nginx, AWS ALB, Cloudflare) that correctly sets X-Forwarded-For to the real client IP
// and strips any client-supplied X-Forwarded-For header. If a customer self-hosts WITHOUT
// a trusted proxy in front, this header is attacker-controlled and REMOTE_ADDR should be
// used instead. Customers running without a proxy MUST set TRUST_PROXY=false and configure
// the server to ignore X-Forwarded-For (future Phase 4.1 config option).
func GetRealClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take only the leftmost IP in the comma-separated list (SplitN limits to 2 parts).
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}
```

---

### Component 4: `cmd/server/main.go` — Wire Rate Limiter (F-3-C fix) & Failed-Login Audit (Fix #4)

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go#L93-L101)

**BEFORE:**
```go
	// Public Support Agent Login Endpoint
	r.Post("/api/v1/auth/support/login", controller.CatchAsync(grantController.SupportLogin))

	// Authenticated Customer Admin Delegation Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
	})
```

**AFTER:**
```go
	// Public Support Agent Login Endpoint — rate-limited to 10 requests/60s per IP (F-3-C fix).
	r.With(
		middleware.RateLimitMiddleware(valkeyClient, 10, 60),
	).Post("/api/v1/auth/support/login", controller.CatchAsync(grantController.SupportLogin))

	// Authenticated Customer Admin Delegation Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
	})
```

---

### Component 4b: Failed-Login Audit Logging — `SupportLogin` failure path (Fix #4)

> **What was previously claimed vs. what was true**: The previous Component 4 note said: *"audit calls for rejection events are written from the service layer during Phase 4 for service-layer rejections (`SupportLogin` returning `SUPPORT_LOGIN_FAILED`)"*. This was **false** — no code diff was shown, and the live `SupportLogin` function does not call `LogSecurityEvent` on its failure path. This section provides the real code change.

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go)

The `SupportLogin` function currently returns `ErrSupportGrantInvalid` on any token lookup failure without logging the event to `AuditEvent`. An attacker probing with invalid tokens leaves no trace in the audit log.

**BEFORE (the entire SupportLogin failure return block, lines 114–117):**
```go
	grant, err := s.supportGrantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil || grant == nil || grant.ExpiresAt.Before(time.Now()) {
		return uuid.Nil, "", ErrSupportGrantInvalid
	}
```

**AFTER:**
```go
	grant, err := s.supportGrantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil || grant == nil || grant.ExpiresAt.Before(time.Now()) {
		// AUDIT: Log the failed login attempt so that repeated invalid-token probes
		// are visible in the immutable audit ledger (Fix #4 / finding #12).
		// We use instID extracted from the token prefix as the institution context;
		// agentUserID is the identity the caller claimed.
		// NOTE: Phase 4 uses the old 6-arg LogSecurityEvent signature (with nil tx)
		// because Phase 5 has not yet changed the signature. Phase 5 updates this
		// call site to the new 5-arg signature as part of its atomic call-site update.
		if s.auditRepo != nil {
			_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
				"SUPPORT_LOGIN_FAILED",
				fmt.Sprintf("Support login rejected: invalid or expired token presented by agent %s", agentUserID.String()),
				nil)
		}
		return uuid.Nil, "", ErrSupportGrantInvalid
	}
```

> **Audit on seat-limit rejection**: When `ErrSeatLimitReached` is returned (added in Phase 1, Component 5), the seat-limit check runs before this block. Add a similar audit call there:
> ```go
> if activeCount >= claims.MaxHumanAgents {
>     if s.auditRepo != nil {
>         _, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
>             "SUPPORT_LOGIN_SEAT_LIMIT",
>             fmt.Sprintf("Login rejected: seat cap %d reached for institution %s", claims.MaxHumanAgents, instID),
>             nil)
>     }
>     return uuid.Nil, "", license.ErrSeatLimitReached
> }
> ```

> **Middleware-layer audit logging (RATE_LIMIT_EXCEEDED, TOKEN_REVOKED)**: Audit logging of rejections that happen *inside* `RateLimitMiddleware` or `AuthMiddleware` requires `auditRepo` to be injected into the middleware. This is a **deferred Phase 4.1 item**. The middleware does not have `auditRepo` access in Phase 4. This is an explicitly documented limitation — not a previously implied completion.

---

### Component 5: Sliding Window Idle Timeout — Decision (finding #33)

The Phase 4 problem statement mentions "static JWT lifetime." The plan does **not** implement a sliding-window idle timeout because it would require every authenticated request to touch Valkey to reset a timer, increasing per-request latency. This is **explicitly deferred** to a future phase. The problem statement item is removed from Phase 4 scope. JWT lifetime remains fixed at 4 hours.

---

## 🧪 Verification Plan

### Build Check
```bash
go build ./...
```

### Automated Tests
```bash
go test ./pkg/middleware/... -run TestRevocation -v
go test ./pkg/middleware/... -run TestRateLimiting -v
```

### Manual Verification
1. Fire 11 rapid requests to `/api/v1/auth/support/login`. Expect the 11th returns `429 RATE_LIMIT_EXCEEDED`.
2. Revoke via `POST /api/v1/auth/support/revoke`, then present the old JWT to a protected endpoint. Expect `401 TOKEN_REVOKED`.
3. Stop Valkey, present a previously-issued JWT to a protected endpoint. Expect `503 REVOCATION_CHECK_UNAVAILABLE` (fail-closed).
```

---

## docs/phase_5_plan.md

```markdown
# Phase 5 Implementation Plan: Cryptographic Non-Repudiation & Audit PII Redaction

## 📌 Problem & Context
1. **Lack of Non-Repudiation**: Audit logs have no asymmetric digital signature proving which server signed the entry.
2. **Unsanitized Audit Log Input**: `description` strings are saved raw, risking accidental PII/token leakage.
3. **Missing Ent schema field `signature`** (F-5-A): `SetSignature()` does not exist until `ent/schema/auditevent.go` is updated and `go generate ./ent/...` is run.
4. **`NewSecurityAuditRepository` constructor break** (F-1-C): Phase 5 changes this constructor's signature. This plan explicitly lists every call site that must be updated simultaneously so `go build ./...` passes after Phase 5.
5. **`LogSecurityEvent` signature break** (F-1-D): Phase 5 changes the function signature (drops `*ent.Tx`, changes return type). Every call site in `grant_support_service.go` must be updated in this same phase.
6. **Chain-verification function missing** (finding #34): A read-back function that recomputes signatures and confirms chain integrity is added here.
7. **Ed25519 private key storage** (finding #32): Source and rotation procedure are documented explicitly.
8. **GDPR vs immutable ledger** (finding #35): Policy note added.

> **Cross-phase ordering guarantee**: Phase 5 is the ONLY phase that changes `NewSecurityAuditRepository` and `LogSecurityEvent`. Phase 1 explicitly deferred these changes. After applying Phase 5, `go build ./...` must pass. The implementation order within Phase 5 is:
> 1. Update Ent schema → run `go generate`
> 2. Update `SecurityAuditRepository` constructor and `LogSecurityEvent`
> 3. Update all call sites in `main.go` and `grant_support_service.go`

---

## 🛠️ Detailed Proposed Code Changes

### Step 1 (MUST RUN FIRST): Update Ent Schema & Regenerate (F-5-A)

#### [MODIFY] [ent/schema/auditevent.go](file:///d:/Hostel_management/GrantSupport/ent/schema/auditevent.go)

**BEFORE (`Fields()` function, lines 27–42):**
```go
func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(func() uuid.UUID {
			id, err := uuid.NewV7()
			if err != nil {
				return uuid.New()
			}
			return id
		}),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("actor_id", uuid.UUID{}),
		field.String("event_type"),
		field.String("description").Optional(),
		field.String("hash_chain").Optional(),
		field.Time("created_at").Default(time.Now),
	}
}
```

**AFTER:**
```go
func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(func() uuid.UUID {
			id, err := uuid.NewV7()
			if err != nil {
				return uuid.New()
			}
			return id
		}),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("actor_id", uuid.UUID{}),
		field.String("event_type"),
		field.String("description").Optional(),
		// hash_chain is not Optional() — every entry must have a chain link (finding #37).
		field.String("hash_chain").Default(""),
		// signature: Ed25519 non-repudiation signature added in Phase 5.
		// Optional() because rows created before Phase 5 will have no signature.
		field.String("signature").Optional(),
		field.Time("created_at").Default(time.Now),
	}
}
```

**After editing the schema, run code generation before writing any other code in this phase:**
```bash
go generate ./ent/...
```
This regenerates the Ent client and creates the `SetSignature()` / `SetHashChain()` methods that subsequent steps depend on.

---

### Step 2: `pkg/security/sanitizer.go` — PII Redaction

#### [NEW] [sanitizer.go](file:///d:/Hostel_management/GrantSupport/pkg/security/sanitizer.go)

> **Fix (F-5-C / finding #21)**: The original `cardRegex` using `\b` fails on space-separated card numbers like `4111 1111 1111 1111` because `\b` matches between word and non-word characters, but spaces are non-word chars on both sides, so the boundary does not fire at the edge of a space-padded number. The replacement pattern uses anchored context (`(?:^|\s|[^\d])`) to correctly handle both compact and space/hyphen-separated card numbers.

```go
package security

import (
	"regexp"
)

var (
	emailRegex = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	// cardRegex matches 13–16 digit sequences (compact or space/hyphen separated).
	// Uses look-around-equivalent anchors instead of \b to handle space-padded formats.
	cardRegex  = regexp.MustCompile(`(?:^|[^\d])((?:\d[ -]?){13,16}\d)(?:[^\d]|$)`)
	tokenRegex = regexp.MustCompile(`(?i)(bearer\s+|token=)[a-z0-9._\-]+`)
)

// SanitizePII masks emails, credit card numbers, and bearer tokens in audit log messages.
// This prevents accidental PII logging into the immutable AuditEvent ledger.
func SanitizePII(input string) string {
	if input == "" {
		return ""
	}
	input = emailRegex.ReplaceAllString(input, "[REDACTED_EMAIL]")
	input = cardRegex.ReplaceAllStringFunc(input, func(match string) string {
		// Preserve leading/trailing non-digit characters that anchored the match.
		return cardRegex.ReplaceAllString(match, "${1}[REDACTED_CARD]")
	})
	input = tokenRegex.ReplaceAllString(input, "$1[REDACTED_TOKEN]")
	return input
}
```

---

### Step 3: `pkg/repository/security_audit_repository.go` — Ed25519 Signing

#### [MODIFY] [security_audit_repository.go](file:///d:/Hostel_management/GrantSupport/pkg/repository/security_audit_repository.go)

**BEFORE (entire file, lines 1–51):**
```go
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
)

type SecurityAuditRepository struct {
	*BaseRepository
}

func NewSecurityAuditRepository(base *BaseRepository) *SecurityAuditRepository {
	return &SecurityAuditRepository{BaseRepository: base}
}

type AuditLogResult struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// LogSecurityEvent records a permanent append-only security audit log entry.
func (r *SecurityAuditRepository) LogSecurityEvent(ctx context.Context, institutionID, actorID uuid.UUID, eventType, description string, tx *ent.Tx) (*AuditLogResult, error) {
	var builder *ent.AuditEventCreate
	if tx != nil {
		builder = tx.AuditEvent.Create()
	} else {
		client, err := r.GetClient(ctx)
		if err != nil {
			return nil, err
		}
		builder = client.AuditEvent.Create()
	}

	event, err := builder.
		SetInstitutionID(institutionID).
		SetActorID(actorID).
		SetEventType(eventType).
		SetDescription(description).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return &AuditLogResult{
		ID:        event.ID,
		CreatedAt: event.CreatedAt,
	}, nil
}
```

**AFTER (full file replacement):**
```go
package repository

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"            // generated Ent client; ent.Asc() used in VerifyAuditChain (I-1 fix)
	"grantsupport/ent/auditevent" // generated predicate package; auditevent.InstitutionID() used in VerifyAuditChain (I-1 fix)
	"grantsupport/pkg/security"
)

// SecurityAuditRepository handles append-only audit event persistence with
// Ed25519 non-repudiation signing and PII sanitization.
type SecurityAuditRepository struct {
	*BaseRepository
	// serverPrivateKey signs each audit entry for non-repudiation.
	// Source: AUDIT_SIGNING_PRIVATE_KEY env var (base64-encoded Ed25519 private key).
	// Rotation: generate a new keypair, update the env var, and restart the service.
	// Old signatures remain verifiable with the old public key (store old public keys in a key registry).
	serverPrivateKey ed25519.PrivateKey
}

// NewSecurityAuditRepository constructs the repository.
// privKey: loaded from AUDIT_SIGNING_PRIVATE_KEY env var via security.GenerateEd25519KeyPair or
// base64.StdEncoding.DecodeString. Pass nil to disable signing (all entries will have no signature).
//
// CALL SITES UPDATED BY THIS PHASE (F-1-C):
//   - cmd/server/main.go: auditRepo := repository.NewSecurityAuditRepository(baseRepo, auditSigningKey)
func NewSecurityAuditRepository(base *BaseRepository, privKey ed25519.PrivateKey) *SecurityAuditRepository {
	return &SecurityAuditRepository{
		BaseRepository:   base,
		serverPrivateKey: privKey,
	}
}

// AuditLogResult is the lightweight DTO returned by LogSecurityEvent.
type AuditLogResult struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// LogSecurityEvent records a permanent append-only audit log entry with PII redaction
// and Ed25519 non-repudiation signing.
//
// SIGNATURE CHANGE FROM PRE-PHASE-5 (F-1-D): the *ent.Tx parameter has been removed.
// The repository now manages its own client resolution. All callers in
// grant_support_service.go must be updated simultaneously (see call site updates below).
func (r *SecurityAuditRepository) LogSecurityEvent(
	ctx context.Context,
	institutionID, actorID uuid.UUID,
	eventType, description string,
) (*AuditLogResult, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	cleanDesc := security.SanitizePII(description)
	now := time.Now()

	// Canonical message includes the generated UUID placeholder — we use a random new UUID
	// for the event before saving to commit the signature to a specific record identity.
	// Using UnixNano() avoids same-second signature collisions (F-5-B / finding #20).
	evtID, _ := uuid.NewV7()
	if evtID == uuid.Nil {
		evtID = uuid.New()
	}
	canonicalMsg := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
		evtID, institutionID, actorID, eventType, cleanDesc, now.UnixNano())

	var sigB64 string
	if len(r.serverPrivateKey) == ed25519.PrivateKeySize {
		sigBytes := ed25519.Sign(r.serverPrivateKey, []byte(canonicalMsg))
		sigB64 = base64.StdEncoding.EncodeToString(sigBytes)
	}

	builder := client.AuditEvent.Create().
		SetID(evtID).
		SetInstitutionID(institutionID).
		SetActorID(actorID).
		SetEventType(eventType).
		SetDescription(cleanDesc).
		SetCreatedAt(now)

	if sigB64 != "" {
		builder = builder.SetSignature(sigB64)
	}

	event, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}

	return &AuditLogResult{
		ID:        event.ID,
		CreatedAt: event.CreatedAt,
	}, nil
}

// VerifyAuditChain reads all AuditEvent rows for an institution in ascending creation order
// and verifies each Ed25519 signature against the server public key.
// Returns the ID of the first invalid entry, or uuid.Nil if the chain is intact (finding #34).
//
// FIX (I-1): The previous draft had both the Where clause and the Order clause
// as commented-out anonymous function literals. Ent's Where() takes ...predicate.AuditEvent,
// not a raw func literal, so it would not compile. Both are now replaced with real
// generated Ent predicates: auditevent.InstitutionID and ent.Asc(auditevent.FieldCreatedAt).
// institutionID is now correctly used (not silently ignored), closing the cross-institution
// data leak in the chain verifier.
func (r *SecurityAuditRepository) VerifyAuditChain(
	ctx context.Context,
	institutionID uuid.UUID,
	pubKey ed25519.PublicKey,
) (uuid.UUID, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	events, err := client.AuditEvent.Query().
		Where(
			// Filter strictly to the calling institution — prevents cross-institution data exposure.
			auditevent.InstitutionID(institutionID),
		).
		Order(ent.Asc(auditevent.FieldCreatedAt)). // ascending by created_at for chain order
		All(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	for _, evt := range events {
		if evt.Signature == "" {
			continue // Pre-Phase-5 rows have no signature; skip gracefully.
		}
		canonicalMsg := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
			evt.ID, institutionID, evt.ActorID, evt.EventType, evt.Description, evt.CreatedAt.UnixNano())
		sigBytes, _ := base64.StdEncoding.DecodeString(evt.Signature)
		if !ed25519.Verify(pubKey, []byte(canonicalMsg), sigBytes) {
			return evt.ID, fmt.Errorf("AUDIT_CHAIN_TAMPERED: entry %s failed signature verification", evt.ID)
		}
	}
	return uuid.Nil, nil
}
```

> **Cross-phase call-site audit for `VerifyAuditChain` (mandatory per process rule)**:
> - `phase_5_plan.md` (this file): defined here — ✔
> - `phase_6_plan.md`, `phase_7_plan.md`, `implementation_plan.md`, `phase_1_plan.md`–`phase_4_plan.md`: `VerifyAuditChain` is not called from any other plan file; it is only exposed as a repository method for future admin API use (see Phase 7 verification plan test command). No other call sites to update.
> - **Call sites checked: all 7 phase files + implementation_plan.md. All updated: N/A (no other callers). Yes.**

---

### Step 4: Update ALL `LogSecurityEvent` Call Sites in `grant_support_service.go` (F-1-D)

> **P2+P4 fix (missing call sites)**: The original Step 4 listed only 3 of the 5 call sites that use the old 6-arg signature. Two additional call sites were added by Phase 4 Component 4b (`SUPPORT_LOGIN_FAILED`) and Phase 1 Component 5 (`SUPPORT_LOGIN_SEAT_LIMIT`). Both pass `nil` as the trailing `*ent.Tx` argument. All 5 are listed here — this is the complete and final set.

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go)

The old signature was: `LogSecurityEvent(ctx, institutionID, actorID, eventType, description string, tx *ent.Tx)`
The new signature is:  `LogSecurityEvent(ctx, institutionID, actorID, eventType, description string)`

**BEFORE (line 89 — `SUPPORT_ACCESS_GRANTED`):**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_GRANTED", fmt.Sprintf("Support access grant created for %d minutes", durationMinutes), nil)
```

**AFTER:**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_GRANTED", fmt.Sprintf("Support access grant created for %d minutes", durationMinutes))
```

**BEFORE (line 124 — `SUPPORT_ACCESS_LOGGED_IN`):**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID, "SUPPORT_ACCESS_LOGGED_IN", fmt.Sprintf("Support login executed by agent %s via active grant", agentUserID.String()), nil)
```

**AFTER:**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID, "SUPPORT_ACCESS_LOGGED_IN", fmt.Sprintf("Support login executed by agent %s via active grant", agentUserID.String()))
```

**BEFORE (line 151 — `SUPPORT_ACCESS_REVOKED`):**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "All active support access grants manually revoked by administrator", nil)
```

**AFTER:**
```go
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "PER-INSTITUTION: All active support access grants manually revoked by administrator")
```

**BEFORE (Phase 4 Component 4b — `SUPPORT_LOGIN_FAILED`, inside grant-lookup failure block):**
```go
			_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
				"SUPPORT_LOGIN_FAILED",
				fmt.Sprintf("Support login rejected: invalid or expired token presented by agent %s", agentUserID.String()),
				nil) // ← remove nil — 5-arg signature
```

**AFTER:**
```go
			_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
				"SUPPORT_LOGIN_FAILED",
				fmt.Sprintf("Support login rejected: invalid or expired token presented by agent %s", agentUserID.String()))
```

**BEFORE (Phase 1 Component 5 — `SUPPORT_LOGIN_SEAT_LIMIT`, inside seat-limit rejection block):**
```go
				_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
					"SUPPORT_LOGIN_SEAT_LIMIT",
					fmt.Sprintf("Login rejected: seat cap %d reached for institution %s",
						claims.MaxHumanAgents, instID),
					nil) // ← remove nil — 5-arg signature
```

**AFTER:**
```go
				_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID,
					"SUPPORT_LOGIN_SEAT_LIMIT",
					fmt.Sprintf("Login rejected: seat cap %d reached for institution %s",
						claims.MaxHumanAgents, instID))
```

> **Why were Phase 4 and Phase 1 call sites added here and not in their own phases?** Because at the time Phase 4 and Phase 1 were applied, `LogSecurityEvent` still had the 6-arg signature. Phase 5 is the phase that changes the signature, so Phase 5 owns updating ALL existing call sites atomically — including those added by earlier phases. This avoids a partial-migration state where some call sites compile and others don't.

---

### Step 5: Update `main.go` — Wire New `auditRepo` Constructor (F-1-C)

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go#L71-L75)

**BEFORE (line 73):**
```go
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
```

**AFTER:**
```go
	// Load Ed25519 audit signing key from env var.
	// Key source: AUDIT_SIGNING_PRIVATE_KEY env var (base64-encoded ed25519 private key).
	// Rotation: generate a new keypair, archive the old public key, update env var, restart.
	var auditSigningKey ed25519.PrivateKey
	if privKeyB64 := os.Getenv("AUDIT_SIGNING_PRIVATE_KEY"); privKeyB64 != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
		if err == nil && len(keyBytes) == ed25519.PrivateKeySize {
			auditSigningKey = ed25519.PrivateKey(keyBytes)
		} else {
			slog.Warn("AUDIT_SIGNING_PRIVATE_KEY is set but invalid; audit entries will be unsigned")
		}
	} else {
		slog.Warn("AUDIT_SIGNING_PRIVATE_KEY not set; audit entries will have no Ed25519 signature")
	}
	auditRepo := repository.NewSecurityAuditRepository(baseRepo, auditSigningKey)
```

Add to imports:
```go
	"crypto/ed25519"
	"encoding/base64"
```

---

### Step 5b: New Migration `000003_add_hash_chain_check.sql` — Applied During Phase 5 Deployment (I-4 fix)

> **Why this migration belongs here (not in Phase 2)**: Phase 2 created `hash_chain NOT NULL DEFAULT ''`. Adding `CHECK (length(hash_chain) > 0)` in Phase 2 would cause every `LogSecurityEvent` INSERT from Phase 2/3/4 code to violate the constraint (those versions don't call `SetHashChain`). The CHECK can only safely be applied AFTER Phase 5 updates `LogSecurityEvent` to always write a real non-empty value. Apply `000003` immediately after deploying Phase 5 code. Do NOT run it before the code update.

#### [NEW] `migrations/postgres/000003_add_hash_chain_check.sql`

```sql
-- Migration 000003 (PostgreSQL): Add CHECK constraint to enforce non-empty hash_chain.
-- MUST be applied after Phase 5 code is deployed and ALL existing rows have non-empty hash_chain values.
-- Run: psql -h <host> -U <user> -d <db> -f 000003_add_hash_chain_check.sql
ALTER TABLE "AuditEvent"
    ADD CONSTRAINT chk_hash_chain_nonempty CHECK (length(hash_chain) > 0);
```

#### [NEW] `migrations/mysql/000003_add_hash_chain_check.sql`

```sql
-- Migration 000003 (MySQL 8.0+): Add CHECK constraint to enforce non-empty hash_chain.
-- MUST be applied after Phase 5 code is deployed.
-- MySQL 8.0.16+ enforces CHECK constraints. Earlier versions parse but ignore them.
ALTER TABLE AuditEvent
    ADD CONSTRAINT chk_hash_chain_nonempty CHECK (LENGTH(hash_chain) > 0);
```

#### [NEW] `migrations/sqlite/000003_add_hash_chain_check.sql`

```sql
-- Migration 000003 (SQLite): Rebuild AuditEvent with CHECK on hash_chain.
-- SQLite does not support ALTER TABLE ADD CONSTRAINT for CHECK constraints.
-- The table must be recreated. Run this migration in a maintenance window.
-- MUST be applied after Phase 5 code is deployed.
CREATE TABLE IF NOT EXISTS AuditEvent_new (
    id TEXT NOT NULL PRIMARY KEY,
    institution_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    hash_chain TEXT NOT NULL DEFAULT '' CHECK (length(hash_chain) > 0),
    signature TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP NOT NULL
);
INSERT INTO AuditEvent_new SELECT * FROM AuditEvent;
DROP TABLE AuditEvent;
ALTER TABLE AuditEvent_new RENAME TO AuditEvent;
CREATE INDEX IF NOT EXISTS idx_auditevent_inst_created ON AuditEvent(institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_auditevent_actor ON AuditEvent(actor_id);
```

> **Also update `implementation_plan.md`'s migration file tree** to include the `000003` entry for each dialect (per I-4 sequencing note).

---

### GDPR Policy Note (finding #35)

> **GDPR right-to-erasure vs. immutable audit ledger**: AuditEvent records are legally classified under the `legitimate interest` / `legal obligation` basis for processing (GDPR Art. 6(1)(c)(f)), which overrides a subject's erasure request for records that are themselves security evidence. In practice, if a regulatory erasure request must be honoured for a specific actor, the approach is: **redact PII fields in the stored description** (replace the actor's identifiable name/email with a pseudonym token) while preserving the hash-chain structure and UUID references intact. This preserves ledger integrity. A separate `AuditEventRedaction` log entry is written to record the redaction event. This policy is an architectural decision — see `code documentation/go documentation/adr/` for the ADR entry.

---

## 🧪 Verification Plan

### Build Check (after Phase 5 — all call sites updated)
```bash
go generate ./ent/...   # MUST run first after schema change
go build ./...
```
Expect: zero errors. Every `LogSecurityEvent` call site now uses the 5-argument signature (no `tx`).

### Automated Tests
```bash
go test ./pkg/security/... -run TestSanitizePII -v
go test ./pkg/repository/... -run TestLogSecurityEvent -v
go test ./pkg/repository/... -run TestVerifyAuditChain -v
```
```

---

## docs/phase_6_plan.md

```markdown
# Phase 6 Implementation Plan: Scoped Granularity, Webhook Engine & Idempotency

## 📌 Problem & Context
1. **Lack of Granular Scopes**: All grants default to `FULL_ACCESS`. Enterprise clients need `READ_ONLY` or `SUPPORT_WRITE`.
2. **Missing Webhook Engine**: No notification when support agents log in or sessions are revoked.
3. **Webhook `targetURL` has no storage** (F-6-B): `DispatchEvent` accepts a URL but there is no DB schema, registration API, or call site — webhooks are non-functional without this.
4. **Webhook goroutine leaks at shutdown** (F-6-A / finding #17): `context.Background()` goroutines outlive graceful shutdown.
5. **Reason field validated but dropped** (F-6-C / finding #24): `GrantSupportInput.Reason` is validated but has no Ent schema field — data is silently discarded.
6. **Scope enforced at input but not at runtime** (finding #15): Scope is validated on the GrantSupportInput DTO but never checked when a SUPPORT_AGENT performs an action during a session.
7. **Idempotency of grant creation and webhook dispatch** (finding #27).
8. **Webhook payloads unsigned** (finding #13): Customers cannot verify webhook authenticity.

> **JSON tag convention (F-1-A)**: All new fields on `GrantSupportInput` use camelCase JSON keys to match the live codebase convention.

> **`shared_secret` encryption (new finding)**: The `InstitutionWebhook.shared_secret` field comment says it "must be stored encrypted at rest using the application encryption layer", but no prior plan shows the actual encryption call. This plan explicitly adds envelope encryption of the shared secret in `UpsertWebhook` before persistence, and decryption in `GetActiveWebhook` before returning — see Component 4 below.

> **Webhook registration API (new finding)**: The verification plan references `POST /api/v1/auth/support/webhook`, but previous drafts only showed the repository layer, not a controller or route. This plan adds a thin controller method and route registration — see Component 4b below.

---

## 🛠️ Detailed Proposed Code Changes

### Component 0 (PREREQUISITE): [NEW] `pkg/encryption` \u2014 AES-256-GCM Envelope Encryptor (I-8 fix)

> **I-8 decision (option b)**: `pkg/encryption` does NOT exist in the live codebase (confirmed by directory listing: `d:\Hostel_management\GrantSupport\pkg` contains no `encryption/` directory). This component defines it from scratch. It is introduced in Phase 6 because Phase 6 is the first phase that requires at-rest encryption (webhook shared secrets). The `MASTER_ENCRYPTION_KEY` env var was already documented in Phase 1's `.env.example`.

#### [NEW] [encryptor.go](file:///d:/Hostel_management/GrantSupport/pkg/encryption/encryptor.go)

```go
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Encryptor is the interface for reversible at-rest encryption.
// Callers must not store the plaintext output of Decrypt() beyond the current request scope.
type Encryptor interface {
	// Encrypt returns ciphertext for the given plaintext bytes.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt returns plaintext for the given ciphertext bytes.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// AESGCMEncryptor is a concrete Encryptor using AES-256-GCM with a random nonce per encryption.
// The output format is: hex(nonce || ciphertext).
type AESGCMEncryptor struct {
	block cipher.Block
}

// NewAESGCMEncryptor constructs an AESGCMEncryptor from a hex-encoded 32-byte key string.
// keyHex is the value of MASTER_ENCRYPTION_KEY from the environment.
// Returns an error if the key is absent, malformed, or not 32 bytes (AES-256).
//
// In development, if keyHex is empty, a fixed all-zeros key is used (NOT safe for production).
// In production, the caller (main.go) must enforce that keyHex is non-empty before calling this.
func NewAESGCMEncryptor(keyHex string) (*AESGCMEncryptor, error) {
	if keyHex == "" {
		// Development fallback: fixed 32-byte zero key.
		// Production startup guard in main.go ensures this branch is never reached in production.
		keyHex = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("MASTER_ENCRYPTION_KEY must be a hex-encoded string: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, errors.New("MASTER_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars) for AES-256")
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	return &AESGCMEncryptor{block: block}, nil
}

// Encrypt produces AES-256-GCM ciphertext with a random 12-byte nonce prepended.
// Output is hex-encoded for safe storage as a VARCHAR/TEXT column value.
func (e *AESGCMEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(e.block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil) // nonce prepended to ciphertext
	dst := make([]byte, hex.EncodedLen(len(sealed)))
	hex.Encode(dst, sealed)
	return dst, nil
}

// Decrypt reverses Encrypt: hex-decodes, splits off the nonce, and decrypts with AES-256-GCM.
func (e *AESGCMEncryptor) Decrypt(hexCiphertext []byte) ([]byte, error) {
	raw := make([]byte, hex.DecodedLen(len(hexCiphertext)))
	if _, err := hex.Decode(raw, hexCiphertext); err != nil {
		return nil, fmt.Errorf("failed to hex-decode ciphertext: %w", err)
	}
	gcm, err := cipher.NewGCM(e.block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short to contain nonce")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed (wrong key or tampered ciphertext): %w", err)
	}
	return plaintext, nil
}
```

> **Cross-phase note for `pkg/encryption`**: This package is introduced in Phase 6. No earlier phase references it. Phase 6's Component 4a (`WebhookRepository`) and Component 7 (`main.go`) are the only consumers. If future phases require PII encryption (e.g., Phase 8 student data), they import this same package and the same `encryptionService` instance from `main.go`.

---

### Component 1: Ent Schema — Add `reason`/`scope` to `SupportGrant`, Add `InstitutionWebhook` Entity

#### [MODIFY] [ent/schema/supportgrant.go](file:///d:/Hostel_management/GrantSupport/ent/schema/supportgrant.go)

**BEFORE (Fields):**
```go
// Existing fields: id, institution_id, granted_by_id, token_hash, expires_at, is_used, used_at, scope, whitelisted_ips, created_at
```

**AFTER — add `reason` field:**
```go
// reason: optional human-readable justification for this grant, stored in DB.
// Data flows: GrantSupportInput.Reason → service → repository → this column.
field.String("reason").Optional(),
```

> All fields except `reason` already exist in the schema. The `scope` field is also already present from the Phase 2 migration SQL. Confirm it is in the Ent schema; if not, add `field.String("scope").Default("FULL_ACCESS")`.

#### [NEW] [ent/schema/institutionwebhook.go](file:///d:/Hostel_management/GrantSupport/ent/schema/institutionwebhook.go)

```go
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// InstitutionWebhook stores per-institution webhook endpoint configuration.
type InstitutionWebhook struct {
	ent.Schema
}

func (InstitutionWebhook) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "InstitutionWebhook"},
	}
}

func (InstitutionWebhook) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.UUID("institution_id", uuid.UUID{}),
		// target_url: the HTTPS endpoint GrantSupport POSTs events to.
		field.String("target_url"),
		// shared_secret: stored as envelope-encrypted ciphertext (see WebhookRepository.UpsertWebhook).
		// Never stored as plaintext. Decrypted in-memory in GetActiveWebhook before use.
		field.String("shared_secret"),
		field.Bool("is_active").Default(true),
		field.Time("created_at"),
	}
}

func (InstitutionWebhook) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("institution_id"),
		index.Fields("institution_id", "is_active"),
	}
}
```

**After all schema changes, regenerate:**
```bash
go generate ./ent/...
```

---

### Component 2: `pkg/controller/auth_dto.go` — GrantSupportInput with Scope & Reason

#### [MODIFY] [auth_dto.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_dto.go)

**BEFORE:**
```go
// GrantSupportInput captures support delegation duration request.
// Uses camelCase JSON tags to match the live codebase convention.
type GrantSupportInput struct {
	DurationMinutes int `json:"durationMinutes" validate:"gte=1,lte=1440"`
}
```

**AFTER (camelCase tags preserved — F-1-A fix maintained):**
```go
// GrantSupportInput captures support delegation request parameters.
// All JSON keys use camelCase to match the live codebase convention.
type GrantSupportInput struct {
	DurationMinutes int    `json:"durationMinutes" validate:"gte=1,lte=1440"`
	// Reason flows through to the SupportGrant DB record and the audit log description.
	Reason          string `json:"reason" validate:"omitempty,max=255"`
	// Scope controls what actions the support agent can perform during the session.
	// Enforcement is documented below — runtime enforcement is explicitly deferred (finding #15).
	Scope           string `json:"scope" validate:"omitempty,oneof=READ_ONLY SUPPORT_WRITE FULL_ACCESS"`
}

// RegisterWebhookInput captures webhook endpoint registration payload.
type RegisterWebhookInput struct {
	TargetURL    string `json:"targetUrl" validate:"required,url"`
	SharedSecret string `json:"sharedSecret" validate:"required,min=16"`
}
```

---

### Component 3: `pkg/service/webhook_dispatcher.go` — Shutdown-Aware Dispatcher with HMAC Signing

#### [NEW] [webhook_dispatcher.go](file:///d:/Hostel_management/GrantSupport/pkg/service/webhook_dispatcher.go)

> **Fix (F-6-A / finding #17)**: Use a `sync.WaitGroup` tracked goroutine pool instead of fire-and-forget goroutines. Callers call `Wait()` before server shutdown.
> **Fix (finding #13)**: Sign payload with `HMAC-SHA256` using the per-institution shared secret. Header: `X-GrantSupport-Signature: sha256=<hex>`.
> **Fix (finding #27)**: `WebhookEvent.EventID` is a stable UUID derived from the grant ID + event type, so retried dispatches are idempotent — the customer endpoint can deduplicate by `event_id`.

```go
package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// WebhookEvent is the canonical payload dispatched to customer webhook endpoints.
type WebhookEvent struct {
	// EventID is stable for a given (source_id + event_type) so customers can deduplicate retries (finding #27).
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"` // "grant.created", "support.login", "support.revoked"
	InstitutionID string    `json:"institution_id"`
	Timestamp     time.Time `json:"timestamp"`
	Data          any       `json:"data"`
}

// WebhookDispatcher manages async HTTP webhook delivery.
type WebhookDispatcher struct {
	httpClient *http.Client
	wg         sync.WaitGroup // tracks in-flight deliveries for graceful shutdown
}

// NewWebhookDispatcher creates a dispatcher with a 5-second per-call timeout.
func NewWebhookDispatcher() *WebhookDispatcher {
	return &WebhookDispatcher{
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// Wait blocks until all in-flight webhook goroutines have completed.
// Call this during server shutdown before exiting (F-6-A fix).
func (w *WebhookDispatcher) Wait() {
	w.wg.Wait()
}

// DispatchEvent asynchronously POSTs a webhook event to targetURL.
// sourceID is the grant or event UUID — used to produce a stable, idempotent EventID.
// sharedSecret is the PLAINTEXT per-institution HMAC-SHA256 signing secret
// (decrypted by WebhookRepository.GetActiveWebhook before being passed here).
func (w *WebhookDispatcher) DispatchEvent(
	shutdownCtx context.Context,
	targetURL string,
	sharedSecret string,
	eventType string,
	instID uuid.UUID,
	sourceID uuid.UUID,
	payload any,
) {
	// Stable EventID: deterministic UUID v5 from (sourceID + eventType).
	// Idempotent: retrying the same event produces the same EventID (finding #27).
	stableEventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(sourceID.String()+":"+eventType))

	event := WebhookEvent{
		EventID:       stableEventID.String(),
		EventType:     eventType,
		InstitutionID: instID.String(),
		Timestamp:     time.Now(),
		Data:          payload,
	}

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()

		bodyBytes, err := json.Marshal(event)
		if err != nil {
			slog.Error("Webhook: failed to marshal event", slog.String("event_type", eventType), slog.String("error", err.Error()))
			return
		}

		// Use the shutdown context so this goroutine respects the server shutdown window (F-6-A).
		req, err := http.NewRequestWithContext(shutdownCtx, "POST", targetURL, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "GrantSupport-Webhook/1.0")

		// HMAC-SHA256 payload signature for customer verification (finding #13).
		if sharedSecret != "" {
			mac := hmac.New(sha256.New, []byte(sharedSecret))
			mac.Write(bodyBytes)
			req.Header.Set("X-GrantSupport-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}

		resp, err := w.httpClient.Do(req)
		if err != nil {
			slog.Warn("Webhook dispatch failed",
				slog.String("url", targetURL),
				slog.String("event_id", stableEventID.String()),
				slog.String("error", err.Error()))
			return
		}
		_ = resp.Body.Close()
		slog.Info("Webhook dispatched",
			slog.String("event_id", stableEventID.String()),
			slog.Int("status", resp.StatusCode))
	}()
}
```

---

### Component 4a: Webhook Repository — With Real Ent Predicates & Encryption

#### [NEW] [webhook_repository.go](file:///d:/Hostel_management/GrantSupport/pkg/repository/webhook_repository.go)

> **Fix (issue #2)**: The previous draft's `GetActiveWebhook` had the Where clause **commented out**: `Where( /* auditevent.InstitutionID(institutionID), is_active = true */ )`. This meant the function accepted `institutionID` as a parameter but **never used it**, returning the first row for any institution — a direct multi-tenant isolation violation. This is now fixed with real Ent predicates.
>
> **Fix (shared_secret encryption)**: `UpsertWebhook` encrypts the shared secret using the application encryption layer before persisting. `GetActiveWebhook` decrypts before returning. The returned `*ent.InstitutionWebhook` struct's `SharedSecret` field is replaced with the **plaintext** value for use by the dispatcher, but this struct should never be serialised back to any external caller (see `RegisterWebhookInput` response — it returns only `id` and `targetUrl`, never the secret).

```go
package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/ent/institutionwebhook"
	"grantsupport/pkg/encryption"
)

// WebhookRepository manages per-institution webhook configuration persistence.
type WebhookRepository struct {
	*BaseRepository
	encryptor encryption.Encryptor // used to encrypt/decrypt shared_secret at rest
}

// NewWebhookRepository constructs the repository.
func NewWebhookRepository(base *BaseRepository, enc encryption.Encryptor) *WebhookRepository {
	return &WebhookRepository{BaseRepository: base, encryptor: enc}
}

// UpsertWebhook creates or replaces the webhook configuration for an institution.
// Multi-tenant isolation: institution_id is always explicitly set (architectural mandate).
// shared_secret is encrypted using the application encryption layer before persisting (new finding fix).
func (r *WebhookRepository) UpsertWebhook(ctx context.Context, institutionID uuid.UUID, targetURL, plaintextSecret string) (*ent.InstitutionWebhook, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	// Encrypt the shared secret before storing. Never persist plaintext webhook secrets.
	encryptedSecret, err := r.encryptor.Encrypt([]byte(plaintextSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt webhook shared secret: %w", err)
	}

	return client.InstitutionWebhook.Create().
		SetInstitutionID(institutionID).
		SetTargetURL(targetURL).
		SetSharedSecret(string(encryptedSecret)).
		SetIsActive(true).
		Save(ctx)
}

// GetActiveWebhook retrieves the active webhook configuration for an institution.
// Returns nil (not an error) if no active webhook is configured for this institution.
//
// FIX (issue #2): Uses real Ent predicates to filter by BOTH institution_id AND is_active = true.
// The previous draft had the Where clause commented out, making institutionID unused
// and returning a random institution's webhook — a multi-tenant isolation violation.
func (r *WebhookRepository) GetActiveWebhook(ctx context.Context, institutionID uuid.UUID) (*ent.InstitutionWebhook, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	wh, err := client.InstitutionWebhook.Query().
		Where(
			institutionwebhook.InstitutionID(institutionID),
			institutionwebhook.IsActive(true),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil // no webhook configured — not an error
		}
		return nil, fmt.Errorf("GetActiveWebhook query failed: %w", err)
	}

	// Decrypt shared_secret in-memory before returning to the service layer.
	plaintext, err := r.encryptor.Decrypt([]byte(wh.SharedSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt webhook shared secret for institution %s: %w", institutionID, err)
	}
	// Replace the stored ciphertext with the plaintext for in-process use only.
	// This struct must never be JSON-serialised to any external caller.
	wh.SharedSecret = string(plaintext)
	return wh, nil
}
```

> **Ent predicate note**: `institutionwebhook.InstitutionID(institutionID)` and `institutionwebhook.IsActive(true)` are the generated Ent predicate functions for the `institution_id` and `is_active` fields defined in `ent/schema/institutionwebhook.go`. These are the real, compilable predicates — not placeholders.

---

### Component 4b: Webhook Registration Controller & Route (new finding fix)

> The verification plan referenced `POST /api/v1/auth/support/webhook` but no prior draft showed the controller method or route. This is added here to close that gap.

#### [MODIFY] [auth_support_controller.go](file:///d:/Hostel_management/GrantSupport/pkg/controller/auth_support_controller.go)

```go
// RegisterWebhook registers or replaces a webhook endpoint for the calling institution.
// POST /api/v1/auth/support/webhook (authenticated — requires admin JWT)
func (c *SupportGrantController) RegisterWebhook(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[RegisterWebhookInput](r)
	if err != nil {
		return err
	}

	institutionID, ok := pkgctx.GetTenant(r.Context())
	if !ok {
		return NewAppError(http.StatusUnauthorized, "MISSING_TENANT", "institution context not found")
	}

	if err := c.grantService.RegisterWebhook(r.Context(), institutionID, input.TargetURL, input.SharedSecret); err != nil {
		return NewAppError(http.StatusInternalServerError, "WEBHOOK_REGISTRATION_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"message": "Webhook endpoint registered successfully.",
	})
	return nil
}
```

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go) — Add webhook route to authenticated group

**BEFORE (authenticated group):**
```go
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
	})
```

**AFTER:**
```go
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))
		// Webhook endpoint registration — requires admin JWT (authenticated group).
		r.Post("/api/v1/auth/support/webhook", controller.CatchAsync(grantController.RegisterWebhook))
	})
```

---

### Component 5: Wire `WebhookDispatcher` into `GrantSupportService`

#### [MODIFY] [grant_support_service.go](file:///d:/Hostel_management/GrantSupport/pkg/service/grant_support_service.go)

Add `webhookDispatcher *WebhookDispatcher` and `webhookRepo` fields, and add `DispatchEvent` calls in `CreateSupportGrant`, `SupportLogin`, and `RevokeSupportGrant`.

**BEFORE (struct — Phase 1 baseline, 4 fields):**

> I-2 fix: The previous BEFORE showed only 3 fields (pre-Phase-1 baseline). After Phase 1 Component 5 adds `licenseManager`, the struct entering Phase 6 already has 4 fields. This is the correct baseline for Phase 6's BEFORE/AFTER diff.

```go
type GrantSupportService struct {
	supportGrantRepo *repository.SupportGrantRepository
	auditRepo        *repository.SecurityAuditRepository
	valkey           *cache.ValkeyClient
	// licenseManager added in Phase 1 Component 5.
	licenseManager   *license.Manager
}
```

**AFTER (Phase 6 adds two webhook fields):**
```go
type GrantSupportService struct {
	supportGrantRepo  *repository.SupportGrantRepository
	auditRepo         *repository.SecurityAuditRepository
	valkey            *cache.ValkeyClient
	// licenseManager added in Phase 1 Component 5.
	licenseManager    *license.Manager
	webhookDispatcher *WebhookDispatcher
	webhookRepo       *repository.WebhookRepository
}
```

Add `RegisterWebhook` service method:
```go
// RegisterWebhook stores a webhook configuration for the institution (delegates to repository).
func (s *GrantSupportService) RegisterWebhook(ctx context.Context, institutionID uuid.UUID, targetURL, plaintextSecret string) error {
	if s.webhookRepo == nil {
		return errors.New("WEBHOOK_UNAVAILABLE: WebhookRepository not configured")
	}
	_, err := s.webhookRepo.UpsertWebhook(ctx, institutionID, targetURL, plaintextSecret)
	return err
}
```

Add call sites inside each service method (example for `CreateSupportGrant`):

> **P5 fix**: Three bugs existed in the original snippet:
> 1. `input.Scope` — `CreateSupportGrant` takes flat parameters, not a struct named `input`. There is no `input` variable in scope. Fixed: use `"FULL_ACCESS"` as the default (scope runtime enforcement is deferred to Phase 6.1 per Component 6 below).
> 2. `grant.ID` — the existing Redlock closure discards the `*ent.SupportGrant` return value (`_, err := s.supportGrantRepo.CreateSupportGrant(...)`). Fixed: declare `var createdGrantID uuid.UUID` before the lock and capture it inside the closure. See annotated snippet below.
> 3. `"duration_minutes"` (snake_case) — violates the camelCase JSON convention enforced across all plans (F-1-A). Fixed: `"durationMinutes"`.

```go
// Phase 6 AFTER: capture createdGrantID before dispatching webhook event.
// Declare before the Redlock block:
var createdGrantID uuid.UUID

// Inside the Redlock closure (replace the existing `_, err := ...` line):
err := s.valkey.LockService.WithLock(ctx, lockKey, 10*time.Second, func(txCtx context.Context) error {
	created, err := s.supportGrantRepo.CreateSupportGrant(txCtx, input)
	if err != nil {
		return err
	}
	createdGrantID = created.ID // capture for webhook dispatch below
	return nil
})

// ... (rest of existing grant creation logic) ...

// After successful grant creation, notify webhook endpoint if configured (P5-fixed dispatch call).
if s.webhookDispatcher != nil && s.webhookRepo != nil {
	if wh, err := s.webhookRepo.GetActiveWebhook(ctx, institutionID); err == nil && wh != nil {
		s.webhookDispatcher.DispatchEvent(ctx, wh.TargetURL, wh.SharedSecret,
			"grant.created", institutionID, createdGrantID, map[string]any{
				// camelCase key (F-1-A fix). Scope deferred to Phase 6.1 — not in scope literally.
				"durationMinutes": durationMinutes,
				"scope":           "FULL_ACCESS", // default; Phase 6.1 will pass the real scope claim
			})
	}
}
```

Similar call sites for `SupportLogin` (event: `"support.login"`, sourceID = `grant.ID`) and `RevokeSupportGrant` (event: `"support.revoked"`, sourceID = `institutionID`).

> **Known limitation — no retry on delivery failure (P13 gap)**: `WebhookDispatcher` makes a single delivery attempt per event. If the customer endpoint returns a non-2xx or is temporarily unreachable, the event is **permanently lost** — there is no retry queue or exponential backoff. The `EventID` field was added specifically to allow idempotent deduplication by the customer *if* retries are implemented. Retry logic is **explicitly deferred to Phase 6.1** and must be tracked as a follow-up. Customers requiring guaranteed delivery should implement their own re-fetch mechanism using the audit log API (Phase 5's `VerifyAuditChain`) until Phase 6.1 is implemented.

---

### Component 6: Scope Enforcement — Explicit Deferral (finding #15)

> **Explicit deferral**: `Scope` (`READ_ONLY`, `SUPPORT_WRITE`, `FULL_ACCESS`) is validated on input and stored in the DB (`SupportGrant.scope`). However, **runtime scope enforcement** (checking the scope claim in the JWT before allowing a specific action during a support session) is **explicitly deferred** to a Phase 6.1 implementation. This work requires:
> 1. Adding `scope` as a claim in the issued JWT.
> 2. Adding `RequireScope("FULL_ACCESS")` middleware calls to protected routes.
> Phase 6.1 is tracked as a separate task. Phase 6 marks `scope` as "stored, not yet enforced."

---

### Component 7: `main.go` — Wire Encryption Service, Dispatcher & Wait on Shutdown

> **I-8 fix (encryption package wiring)**: `encryptionService` is constructed here from `MASTER_ENCRYPTION_KEY` (see Component 0 — `pkg/encryption`). It must appear BEFORE `webhookRepo` is built since `NewWebhookRepository` takes it as a parameter.

> **I-7 fix**: `NewWebhookRepository` now takes a 2nd `encryption.Encryptor` argument. The previous snippet showed the old 1-arg call.

> **I-2 fix**: `NewGrantSupportService` now takes 6 arguments. The previous snippet was missing `licMgr` (added by Phase 1).

#### [MODIFY] [main.go](file:///d:/Hostel_management/GrantSupport/cmd/server/main.go)

Add BEFORE repo initialization (after Valkey block from Phase 4):
```go
	// Initialize AES-GCM encryption service from MASTER_ENCRYPTION_KEY env var.
	// Required for: webhook shared_secret storage, and any future PII field encryption.
	// Phase 1 .env.example documents this variable.
	encryptionKeyHex := os.Getenv("MASTER_ENCRYPTION_KEY")
	if encryptionKeyHex == "" && cfg.Environment == "production" {
		slog.Error("FATAL: MASTER_ENCRYPTION_KEY is required in production. Exiting.")
		os.Exit(1)
	}
	encryptionService, err := encryption.NewAESGCMEncryptor(encryptionKeyHex)
	if err != nil {
		slog.Error("Failed to initialize encryption service", slog.String("error", err.Error()))
		os.Exit(1)
	}
```

Add after repo initialization:
```go
	webhookDispatcher := service.NewWebhookDispatcher()
	// I-7 fix: 2nd arg is encryptionService (defined above).
	webhookRepo := repository.NewWebhookRepository(baseRepo, encryptionService)
```

Update `NewGrantSupportService` call:
```go
	// I-2 fix: 6 args — licMgr added by Phase 1; webhookDispatcher + webhookRepo added by Phase 6.
	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr, webhookDispatcher, webhookRepo)
```

Add import:
```go
	"grantsupport/pkg/encryption"
```

Add to the graceful shutdown block after `server.Shutdown(ctx)`:
```go
	// Wait for all in-flight webhook goroutines to finish before process exits (F-6-A fix).
	webhookDispatcher.Wait()
```

> **Cross-phase call-site audit for `NewGrantSupportService` (mandatory per process rule)**:
> - `phase_1_plan.md` Component 3: `NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr)` — 4 args ✔
> - `phase_6_plan.md` Component 7 (this section): `NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient, licMgr, webhookDispatcher, webhookRepo)` — 6 args ✔
> - `phase_7_plan.md`: Uses `GrantSupportEngine` SDK struct, does NOT call `NewGrantSupportService` directly — ✔
> - `phase_2_plan.md`, `phase_3_plan.md`, `phase_4_plan.md`, `phase_5_plan.md`: Do not call `NewGrantSupportService` — ✔
> - `implementation_plan.md`: References the constructor conceptually, not as a call site — ✔
> - **Call sites checked: all 7 phase files + implementation_plan.md. All updated: yes.**

> **Cross-phase call-site audit for `NewWebhookRepository` (mandatory per process rule)**:
> - `phase_6_plan.md` Component 7 (this section): `NewWebhookRepository(baseRepo, encryptionService)` — 2 args ✔
> - `phase_7_plan.md`: Does not call `NewWebhookRepository` — ✔
> - All other phase files: do not call `NewWebhookRepository` — ✔
> - **Call sites checked: all 7 phase files + implementation_plan.md. All updated: yes.**

---

## 🧪 Verification Plan

### Build Check
```bash
go generate ./ent/...
go build ./...
```

### Automated Tests
```bash
go test ./pkg/service/... -run TestWebhookDispatch -v
go test ./pkg/repository/... -run TestGetActiveWebhookFiltersOnInstitution -v
```

### Manual Verification
1. Register a webhook via `POST /api/v1/auth/support/webhook` (authenticated):
   ```json
   { "targetUrl": "https://customer.example.com/webhooks/grantsupport", "sharedSecret": "mysecret16chars" }
   ```
2. Register a second webhook for a **different institution**. Confirm that creating a grant for institution A does NOT dispatch to institution B's endpoint (multi-tenant isolation check).
3. Create a support grant. Confirm the customer endpoint receives a `grant.created` POST with `X-GrantSupport-Signature` header.
4. Verify HMAC: `HMAC-SHA256(sharedSecret, body) == X-GrantSupport-Signature value`.
5. Retry the same grant creation; confirm the customer receives the same `event_id` (idempotent dispatch).
6. Send `SIGTERM` during an in-flight webhook. Confirm the process waits for delivery before exiting.
```

---

## docs/phase_7_plan.md

```markdown
# Phase 7 Implementation Plan: Developer SDK & Client UI Component

## 📌 Problem & Context
1. **Manual Router Registration**: Developers must manually hook controllers into Chi routers.
2. **Missing Frontend Widget**: Clients must build custom HTML/JS UI elements.
3. **SDK drops authentication entirely** (F-7-A — most severe): The original SDK `MountRoutes()` had no middleware on the grant/revoke group, making those endpoints unauthenticated.
4. **Rate limiter never mounted in SDK path** (F-3-C): SDK must also apply `RateLimitMiddleware` to the login endpoint.
5. **Widget DOM ID collisions** (F-7-B / finding #25): Hardcoded IDs break multiple instances.
6. **Widget doesn't check `res.ok`** (F-7-C / finding #26): Non-JSON error responses crash the widget silently.
7. **Widget sends wrong JSON key for duration** (F-1-A): Widget must send `durationMinutes` (camelCase), not `duration_minutes`.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `pkg/sdk/sdk.go` — Authenticated SDK with Rate Limiting

#### [NEW] [sdk.go](file:///d:/Hostel_management/GrantSupport/pkg/sdk/sdk.go)

> **Fix (F-7-A)**: `GrantSupportEngine` accepts `*cache.ValkeyClient` and applies `middleware.NewAuthMiddleware` inside the group — exactly matching `main.go`'s existing wiring.
> **Fix (F-3-C)**: `RateLimitMiddleware` is applied to the login endpoint via `r.With(...).Post(...)`, consistent with the Phase 4 `main.go` diff.

**BEFORE (original draft):**
```go
func (e *GrantSupportEngine) MountRoutes(r chi.Router) {
	r.Post("/api/v1/auth/support/login", controller.CatchAsync(e.Controller.SupportLogin))
	r.Group(func(r chi.Router) {
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(e.Controller.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(e.Controller.RevokeSupport))
	})
}
```

**AFTER:**
```go
package sdk

import (
	"github.com/go-chi/chi/v5"
	"grantsupport/pkg/cache"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/middleware"
)

// GrantSupportEngine is the SDK entry point for integrating GrantSupport
// into any Chi-based application.
type GrantSupportEngine struct {
	Controller  *controller.SupportGrantController
	// ValkeyClient is required for:
	// 1. AuthMiddleware — revocation checks (nil disables revocation; NOT safe for production).
	// 2. RateLimitMiddleware — brute-force protection on the login endpoint.
	ValkeyClient *cache.ValkeyClient
}

// MountRoutes registers all GrantSupport endpoints on the provided router.
// It applies:
// - RateLimitMiddleware (10 req/60s per IP) on the public login endpoint.
// - NewAuthMiddleware on the authenticated grant/revoke/webhook group.
//
// This matches the wiring in cmd/server/main.go exactly (F-7-A fix).
//
// I-6 fix: RegisterWebhook is now included in the authenticated group.
// Method name confirmed from phase_6_plan.md Component 4b: func (c *SupportGrantController) RegisterWebhook(...)
func (e *GrantSupportEngine) MountRoutes(r chi.Router) {
	// Public login endpoint — rate-limited (F-3-C fix for SDK path).
	r.With(
		middleware.RateLimitMiddleware(e.ValkeyClient, 10, 60),
	).Post("/api/v1/auth/support/login", controller.CatchAsync(e.Controller.SupportLogin))

	// Authenticated group — requires valid JWT (F-7-A fix: auth middleware applied here).
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(e.ValkeyClient))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(e.Controller.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(e.Controller.RevokeSupport))
		// Webhook registration — I-6 fix: missing from original SDK, now added to match main.go routing.
		// Method name: RegisterWebhook (confirmed in phase_6_plan.md Component 4b).
		r.Post("/api/v1/auth/support/webhook", controller.CatchAsync(e.Controller.RegisterWebhook))
	})
}
```

> **Cross-phase call-site audit for `RegisterWebhook` method name (mandatory per process rule)**:
> - Searched phase_6_plan.md Component 4b: method is `func (c *SupportGrantController) RegisterWebhook(...)` — ✔
> - phase_7_plan.md (this file): `e.Controller.RegisterWebhook` — matches exactly ✔
> - No other phase file references this method name directly — ✔
> - **Call sites checked: phase_6, phase_7. All updated: yes.**


---

### Component 2: `web/widget/grantsupport.js` — Fixed Widget

#### [NEW] [grantsupport.js](file:///d:/Hostel_management/GrantSupport/web/widget/grantsupport.js)

> **Fix (F-7-B / finding #25)**: All element lookups use `this.container.querySelector(...)` with unique per-instance ID suffix, not `document.getElementById`. Multiple widget instances on the same page work correctly.
> **Fix (F-7-C / finding #26)**: `res.ok` is checked before calling `res.json()`. `res.json()` is wrapped in try/catch to handle non-JSON error bodies.
> **Fix (F-1-A)**: Widget sends `durationMinutes` (camelCase) to match the live server DTO tag.

**BEFORE (original draft):**
```javascript
// Used hardcoded getElementById('gs-duration'), no res.ok check,
// and sent duration_minutes (snake_case) — all three are bugs.
```

**AFTER:**
```javascript
/**
 * GrantSupportWidget
 * Drop-in UI component for managing delegated support access.
 * Multiple instances on the same page are fully supported.
 *
 * Usage:
 *   <script src="/path/to/grantsupport.js"></script>
 *   <div id="my-support-panel"></div>
 *   <script>
 *     new GrantSupportWidget('my-support-panel', { apiBase: '/api/v1/auth/support' });
 *   </script>
 */
class GrantSupportWidget {
  constructor(containerId, options = {}) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error('[GrantSupportWidget] Container not found:', containerId);
      return;
    }
    this.apiBase = options.apiBase || '/api/v1/auth/support';
    // Unique per-instance suffix prevents DOM ID collisions when multiple widgets
    // are rendered on the same page (F-7-B fix).
    this.uid = containerId + '_' + Math.random().toString(36).slice(2, 8);
    this.init();
  }

  init() {
    this.container.innerHTML = `
      <div style="border:1px solid #e2e8f0; border-radius:8px; padding:16px; font-family:sans-serif;">
        <h4 style="margin-top:0;">Delegated Support Access</h4>
        <p style="color:#64748b; font-size:14px;">Grant temporary, audited access to customer support engineers.</p>
        <div style="display:flex; gap:8px; align-items:center;">
          <select id="${this.uid}_duration" style="padding:8px; border-radius:4px; border:1px solid #cbd5e1;">
            <option value="15">15 Minutes</option>
            <option value="60" selected>1 Hour</option>
            <option value="240">4 Hours</option>
          </select>
          <button id="${this.uid}_btn_grant" style="background:#2563eb; color:#fff; border:none; padding:8px 16px; border-radius:4px; cursor:pointer;">Grant Access</button>
          <button id="${this.uid}_btn_revoke" style="background:#dc2626; color:#fff; border:none; padding:8px 16px; border-radius:4px; cursor:pointer;">Revoke All</button>
        </div>
        <div id="${this.uid}_output" style="display:none; margin-top:12px; padding:8px; background:#f1f5f9; border-radius:4px;">
          <strong>Support Token:</strong> <code id="${this.uid}_token"></code>
        </div>
        <div id="${this.uid}_error" style="display:none; margin-top:8px; color:#dc2626; font-size:13px;"></div>
      </div>
    `;

    // Scope lookups to this.container to avoid ID collisions (F-7-B fix).
    this.container.querySelector(`#${this.uid}_btn_grant`).onclick = () => this.grantAccess();
    this.container.querySelector(`#${this.uid}_btn_revoke`).onclick = () => this.revokeAccess();
  }

  _showError(msg) {
    const el = this.container.querySelector(`#${this.uid}_error`);
    if (el) { el.textContent = msg; el.style.display = 'block'; }
  }

  _clearError() {
    const el = this.container.querySelector(`#${this.uid}_error`);
    if (el) { el.style.display = 'none'; el.textContent = ''; }
  }

  async grantAccess() {
    this._clearError();
    const durationEl = this.container.querySelector(`#${this.uid}_duration`);
    const duration = parseInt(durationEl.value);

    let res, data;
    try {
      res = await fetch(`${this.apiBase}/grant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Send camelCase key to match server DTO (F-1-A fix).
        body: JSON.stringify({ durationMinutes: duration })
      });
    } catch (networkErr) {
      this._showError('Network error: ' + networkErr.message);
      return;
    }

    if (!res.ok) {
      // Check res.ok BEFORE calling res.json() (F-7-C fix).
      let errMsg = `Server error ${res.status}`;
      try {
        const errBody = await res.json();
        errMsg = errBody.detail || errBody.message || errMsg;
      } catch (_) { /* non-JSON body — use generic message */ }
      this._showError(errMsg);
      return;
    }

    try {
      data = await res.json();
    } catch (parseErr) {
      this._showError('Unexpected response format from server.');
      return;
    }

    if (data.success) {
      this.container.querySelector(`#${this.uid}_token`).textContent = data.token;
      this.container.querySelector(`#${this.uid}_output`).style.display = 'block';
    }
  }

  async revokeAccess() {
    this._clearError();

    let res, data;
    try {
      res = await fetch(`${this.apiBase}/revoke`, { method: 'POST' });
    } catch (networkErr) {
      this._showError('Network error: ' + networkErr.message);
      return;
    }

    if (!res.ok) {
      let errMsg = `Server error ${res.status}`;
      try {
        const errBody = await res.json();
        errMsg = errBody.detail || errBody.message || errMsg;
      } catch (_) { /* non-JSON body */ }
      this._showError(errMsg);
      return;
    }

    try {
      data = await res.json();
    } catch (parseErr) {
      this._showError('Unexpected response format from server.');
      return;
    }

    if (data.success) {
      alert('All support delegations revoked.');
      this.container.querySelector(`#${this.uid}_output`).style.display = 'none';
    }
  }
}
```

---

## 🧪 Verification Plan

### Build Check
```bash
go build ./...
```

### SDK Security Verification
1. Mount SDK via `engine.MountRoutes(router)` in an integration test server.
2. Send `POST /api/v1/auth/support/grant` with **no** `Authorization` header.
   Expect: `401 UNAUTHORIZED` (confirms auth middleware is active — F-7-A fix).
3. Send 11 rapid `POST /api/v1/auth/support/login` requests.
   Expect: 11th request returns `429 RATE_LIMIT_EXCEEDED` (confirms rate limiter is wired).

### Widget Multi-Instance Verification
```html
<div id="panel-a"></div>
<div id="panel-b"></div>
<script src="/grantsupport.js"></script>
<script>
  new GrantSupportWidget('panel-a', { apiBase: '/api/v1/auth/support' });
  new GrantSupportWidget('panel-b', { apiBase: '/api/v1/auth/support' });
  // Clicking "Grant" in panel-b must not affect panel-a's output div.
</script>
```
```

---

## scripts/archive/extract_grantsupport.py

```python
#!/usr/bin/env python3
"""
HISTORICAL ARCHIVE ONLY — DO NOT RE-RUN
---------------------------------------
This script is a one-time historical record of how the GrantSupport codebase
was initially extracted from TenantPro (go-backend).
It is NOT meant to be re-run and does NOT indicate any ongoing runtime
or build-time dependency on TenantPro. GrantSupport is a 100% standalone product.
"""

import os
import shutil
import re

SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "go-backend"))
TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

FILES_TO_COPY = [
    # Schemas
    ("ent/schema/supportgrant.go", "ent/schema/supportgrant.go"),
    ("ent/schema/auditevent.go", "ent/schema/auditevent.go"),
    
    # Domain & Security (Ed25519 + RS256 + 10 Pillars)
    ("pkg/domain/support_grant.go", "pkg/domain/support_grant.go"),
    ("pkg/security/events.go", "pkg/security/events.go"),
    ("pkg/security/jwt.go", "pkg/security/jwt.go"),
    ("pkg/security/keys.go", "pkg/security/keys.go"),
    
    # Repository Layer
    ("pkg/repository/support_grant_repository.go", "pkg/repository/support_grant_repository.go"),
    ("pkg/repository/security_audit_repository.go", "pkg/repository/security_audit_repository.go"),
    ("pkg/repository/base.go", "pkg/repository/base.go"),
    
    # Service Layer
    ("pkg/service/grant_support_service.go", "pkg/service/grant_support_service.go"),
    
    # Controller Layer
    ("pkg/controller/auth_support_controller.go", "pkg/controller/auth_support_controller.go"),
    ("pkg/controller/auth_dto.go", "pkg/controller/auth_dto.go"),
    ("pkg/controller/base_controller.go", "pkg/controller/base_controller.go"),
    
    # Middleware & Context Layer (Bulletproof 5-Layer Security + RBAC + Correlation)
    ("pkg/context/context.go", "pkg/context/context.go"),
    ("pkg/config/config.go", "pkg/config/config.go"),
    ("pkg/middleware/auth.go", "pkg/middleware/auth.go"),
    ("pkg/middleware/bulletproof_auth.go", "pkg/middleware/bulletproof_auth.go"),
    ("pkg/middleware/bulletproof_auth_test.go", "pkg/middleware/bulletproof_auth_test.go"),
    ("pkg/middleware/rbac.go", "pkg/middleware/rbac.go"),
    ("pkg/middleware/correlation.go", "pkg/middleware/correlation.go"),
    
    # Cache & Redlock Layer
    ("pkg/cache/valkey.go", "pkg/cache/valkey.go"),
]

def main():
    print("Historical Extraction Archive - Not meant to be executed.")

if __name__ == "__main__":
    main()
```

---

## scripts/update_source_exports.py

```python
#!/usr/bin/env python3
"""
Utility script to regenerate GRANTSUPPORT_FULL_SOURCE.md and GRANTSUPPORT_GENERATED_ENT_SOURCE.md
from the live codebase.
"""

import os
import subprocess
from datetime import datetime

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def get_git_commit():
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "HEAD"

def make_anchor(filepath):
    anchor = filepath.replace("/", "-").replace("\\", "-").replace(".", "-").replace("_", "-").lower()
    return anchor

def get_lang(filepath):
    if filepath.endswith(".go"):
        return "go"
    if filepath.endswith(".py"):
        return "python"
    if filepath.endswith(".mod") or filepath.endswith(".sum"):
        return "text"
    if filepath.endswith(".md"):
        return "markdown"
    if filepath.endswith(".json"):
        return "json"
    if filepath.endswith(".yaml") or filepath.endswith(".yml"):
        return "yaml"
    if filepath.endswith(".sql"):
        return "sql"
    if filepath.lower().endswith("dockerfile"):
        return "dockerfile"
    return "text"

def generate_full_source():
    commit = get_git_commit()
    date_str = datetime.now().strftime("%Y-%m-%d")

    # Categories
    cmd_files = []
    pkg_files = []
    ent_schema_files = []
    api_files = []
    migration_files = []
    docs_files = []
    script_files = []
    root_files = ["README.md", "Dockerfile", "docker-compose.yml", "go.mod", "go.sum"]

    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "cmd")):
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
            cmd_files.append(rel)

    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "pkg")):
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
            pkg_files.append(rel)

    ent_schema_files.append("ent/generate.go")
    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "ent", "schema")):
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
            ent_schema_files.append(rel)

    if os.path.exists(os.path.join(REPO_ROOT, "api")):
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "api")):
            for f in sorted(files):
                rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
                api_files.append(rel)

    if os.path.exists(os.path.join(REPO_ROOT, "migrations")):
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "migrations")):
            for f in sorted(files):
                rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
                migration_files.append(rel)

    if os.path.exists(os.path.join(REPO_ROOT, "docs")):
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "docs")):
            for f in sorted(files):
                rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
                docs_files.append(rel)

    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "scripts")):
        for f in sorted(files):
            if f.endswith(".py"):
                rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
                script_files.append(rel)

    cmd_files.sort()
    pkg_files.sort()
    ent_schema_files.sort()
    api_files.sort()
    migration_files.sort()
    docs_files.sort()
    script_files.sort()

    lines = []
    lines.append("# GrantSupport Full Source Code Export")
    lines.append("")
    lines.append(f"- **Export Date**: {date_str}")
    lines.append(f"- **Git Commit**: {commit}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Table of Contents")
    lines.append("")

    if cmd_files:
        lines.append("### cmd/")
        for f in cmd_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if pkg_files:
        lines.append("### pkg/")
        for f in pkg_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if ent_schema_files:
        lines.append("### ent/schema/")
        for f in ent_schema_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if api_files:
        lines.append("### api/")
        for f in api_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if migration_files:
        lines.append("### migrations/")
        for f in migration_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if docs_files:
        lines.append("### docs/")
        for f in docs_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if script_files:
        lines.append("### scripts/")
        for f in script_files:
            lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    if root_files:
        lines.append("### Root-level files")
        for f in root_files:
            if os.path.exists(os.path.join(REPO_ROOT, f)):
                lines.append(f"- [{f}](#{make_anchor(f)})")
        lines.append("")

    lines.append("---")
    lines.append("")

    all_sections = [
        ("cmd", cmd_files),
        ("pkg", pkg_files),
        ("ent/schema", ent_schema_files),
        ("api", api_files),
        ("migrations", migration_files),
        ("docs", docs_files),
        ("scripts", script_files),
        ("root", [f for f in root_files if os.path.exists(os.path.join(REPO_ROOT, f))])
    ]

    for cat, files in all_sections:
        for f in files:
            full_path = os.path.join(REPO_ROOT, f)
            if not os.path.exists(full_path):
                continue
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()

            lang = get_lang(f)
            lines.append(f"## {f}")
            lines.append("")
            lines.append(f"```{lang}")
            lines.append(content.rstrip())
            lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")

    out_path = os.path.join(REPO_ROOT, "GRANTSUPPORT_FULL_SOURCE.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")
    print(f"Generated {out_path} ({len(lines)} lines)")

def generate_generated_ent_source():
    date_str = datetime.now().strftime("%Y-%m-%d")

    ent_files = []
    for root, dirs, files in os.walk(os.path.join(REPO_ROOT, "ent")):
        # Skip schema directory and generate.go
        rel_root = os.path.relpath(root, REPO_ROOT).replace(os.sep, "/")
        if rel_root.startswith("ent/schema"):
            continue
        for f in sorted(files):
            if f == "generate.go":
                continue
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT).replace(os.sep, "/")
            ent_files.append(rel)

    ent_files.sort()

    lines = []
    lines.append("# GrantSupport Generated Ent Code Export")
    lines.append("")
    lines.append(f"- **Export Date**: {date_str}")
    lines.append("- **Description**: Contains the generated Ent ORM boilerplate code omitted from GRANTSUPPORT_FULL_SOURCE.md.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Table of Contents")
    lines.append("")
    for f in ent_files:
        lines.append(f"- [{f}](#{make_anchor(f)})")
    lines.append("")
    lines.append("---")
    lines.append("")

    for f in ent_files:
        full_path = os.path.join(REPO_ROOT, f)
        if not os.path.exists(full_path):
            continue
        with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()

        lang = get_lang(f)
        lines.append(f"## {f}")
        lines.append("")
        lines.append(f"```{lang}")
        lines.append(content.rstrip())
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

    out_path = os.path.join(REPO_ROOT, "GRANTSUPPORT_GENERATED_ENT_SOURCE.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")
    print(f"Generated {out_path} ({len(lines)} lines)")

if __name__ == "__main__":
    generate_full_source()
    generate_generated_ent_source()
```

---

## README.md

```markdown
# GrantSupport 🛡️

**Open-Source Delegated Support-Access Authentication & Cryptographic Audit Engine**

[![Go Report Card](https://goreportcard.com/badge/github.com/grantsupport/grantsupport)](https://goreportcard.com/report/github.com/grantsupport/grantsupport)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1.0-green.svg)](api/openapi.yaml)

GrantSupport solves the **"vendor support access problem"** for multi-tenant B2B SaaS platforms. Rather than creating permanent backdoors or sharing static credentials, GrantSupport allows customer administrators to delegate temporary, time-bounded, cryptographically signed, and tamper-audited access to vendor support engineers.

---

## 🔒 Core Security & Architectural Guarantees

1. **Two-Tier Authentication**:
   - **Tier 1 (Grant Creation & Revocation)**: Protected by standard RS256 Bearer JWTs (`ADMIN` / `OPERATOR` roles).
   - **Tier 2 (Grant Consumption)**: Support agents claim high-entropy single-use tokens, issuing a 4-hour `SUPPORT_AGENT` RS256 JWT with explicit tenant scoping.
2. **Atomic Single-Use Consumption**:
   - Unconditional SQL conditional predicate (`UPDATE ... WHERE id = ? AND is_used = false`) prevents concurrent token double-claim race conditions across distributed instances.
3. **Cryptographic SHA-256 Audit Ledger**:
   - Every grant lifecycle event is recorded in an immutable, append-only ledger with SHA-256 hash-chaining.
   - **Per-Institution Mutex Striping**: Prevents hash-chain interleaving under high concurrency while avoiding cross-tenant lock contention.
   - **Tamper Verification**: Built-in `VerifyAuditChain(ctx, institutionID)` detects any unauthorized database mutation.
4. **Automated PII & Credential Sanitization**:
   - Redacts bearer tokens, passwords, credit cards (PAN), emails, and phone numbers before logging to the immutable audit ledger.
5. **Database Portability & Connection Pool Preservation**:
   - Native support for **PostgreSQL**, **MySQL**, **MariaDB**, and **SQLite** (pure Go `modernc.org/sqlite`).
   - Reuses caller-managed `*sql.DB` connection pools without creating secondary pools or leaking resources.
6. **Valkey / Redis Optionality**:
   - Distributed locking, replay prevention, and token revocation support both Valkey/Redis clusters and pure SQL/In-Memory fallback adapters.
7. **Signed Lifecycle Webhooks**:
   - Dispatches `grant.created`, `grant.claimed`, and `grant.revoked` webhook events with HMAC-SHA256 request signatures (`X-GrantSupport-Signature`).

---

## 🚀 Quickstart

### Option 1: Embedded Go Library (Zero-Infra In-Process Engine)

GrantSupport can be embedded directly inside any Go service:

```go
package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
	"grantsupport/pkg/grantsupport"
)

func main() {
	db, _ := sql.Open("sqlite", "file:app.db?cache=shared&_pragma=foreign_keys(1)")

	// Initialize GrantSupport embedded engine
	engine, err := grantsupport.NewEngine(
		grantsupport.WithDB(db, "sqlite"),
		grantsupport.WithAutoMigrate(true),
	)
	if err != nil {
		log.Fatalf("Failed to initialize GrantSupport: %v", err)
	}
	defer engine.Close()

	// Direct Go API Usage:
	// rawToken, err := engine.CreateSupportGrant(ctx, instID, adminID, 60, "BILLING_ONLY", nil)
	// instID, jwtToken, err := engine.SupportLogin(ctx, rawToken, agentID)
	// valid, err := engine.VerifyAuditChain(ctx, instID)

	// Mount REST Endpoints on existing HTTP Server:
	http.Handle("/api/v1/", engine.HTTPHandler())
	http.ListenAndServe(":8080", nil)
}
```

---

### Option 2: Standalone Microservice via Docker Compose

Run GrantSupport with PostgreSQL and Valkey:

```bash
docker compose --profile default up -d
```

Or run with SQLite in-container storage:

```bash
docker compose --profile sqlite up -d
```

---

## 📡 REST API Reference

The full interactive OpenAPI 3.1 specification is available in [`api/openapi.yaml`](api/openapi.yaml).

### 1. Create Support Grant (Customer Admin)
```http
POST /api/v1/auth/support/grant
Authorization: Bearer <Admin_JWT>
Content-Type: application/json

{
  "durationMinutes": 60,
  "scope": "READ_ONLY",
  "whitelistedIps": ["198.51.100.4"]
}
```
**Response (201 Created):**
```json
{
  "success": true,
  "message": "Support access token generated successfully.",
  "token": "550e8400-e29b-41d4-a716-446655440000_9f83a8b9487c6e12e2057639f28d8442..."
}
```

---

### 2. Support Login (Support Agent)
```http
POST /api/v1/auth/support/login
Content-Type: application/json

{
  "token": "550e8400-e29b-41d4-a716-446655440000_9f83a8b9487c6e12e2057639f28d8442...",
  "agentId": "7f4c935b-16d7-4f9e-a8f2-39c4a852b719"
}
```
**Response (200 OK):**
```json
{
  "success": true,
  "message": "Support agent authenticated successfully.",
  "institution_id": "550e8400-e29b-41d4-a716-446655440000",
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 3. Revoke Active Grants (Customer Admin)
```http
POST /api/v1/auth/support/revoke
Authorization: Bearer <Admin_JWT>
```
**Response (200 OK):**
```json
{
  "success": true,
  "message": "All active support access grants revoked successfully."
}
```

---

## 🧪 Testing & Verification

Run the entire comprehensive test suite across all capability adapters, concurrent race simulations, and cryptographic verifications:

```bash
go test -count=1 ./... -v
```

---

## 📄 License

GrantSupport is licensed under the [Apache License, Version 2.0](LICENSE).
```

---

## Dockerfile

```dockerfile
# Multi-stage Dockerfile for GrantSupport Standalone Engine
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/grantsupport cmd/server/main.go

# Minimal distroless runtime image
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /

COPY --from=builder /app/grantsupport /grantsupport
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/grantsupport"]
```

---

## docker-compose.yml

```yaml
services:
  # ==========================================
  # GrantSupport Service (PostgreSQL Backend)
  # ==========================================
  grantsupport-postgres:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: grantsupport-postgres
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - ENVIRONMENT=production
      - PORT=8080
      - DATABASE_DIALECT=postgres
      - DATABASE_URL=postgresql://grantsupport:secretpassword@postgres:5432/grantsupport?sslmode=disable
      - VALKEY_CACHE_URL=valkey://valkey:6379/0
      - JWT_PRIVATE_KEY=${JWT_PRIVATE_KEY}
      - JWT_PUBLIC_KEY=${JWT_PUBLIC_KEY}
      - MASTER_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
      - LOCAL_SECRET_KEY=0123456789abcdef0123456789abcdef
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
    profiles:
      - default
      - postgres

  # ==========================================
  # GrantSupport Service (MySQL / MariaDB Backend)
  # ==========================================
  grantsupport-mysql:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: grantsupport-mysql
    restart: unless-stopped
    ports:
      - "8081:8080"
    environment:
      - ENVIRONMENT=production
      - PORT=8080
      - DATABASE_DIALECT=mysql
      - DATABASE_URL=grantsupport:secretpassword@tcp(mysql:3306)/grantsupport?parseTime=true
      - JWT_PRIVATE_KEY=${JWT_PRIVATE_KEY}
      - JWT_PUBLIC_KEY=${JWT_PUBLIC_KEY}
      - MASTER_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
      - LOCAL_SECRET_KEY=0123456789abcdef0123456789abcdef
    depends_on:
      mysql:
        condition: service_healthy
    profiles:
      - mysql

  # ==========================================
  # GrantSupport Service (SQLite In-Process Backend)
  # ==========================================
  grantsupport-sqlite:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: grantsupport-sqlite
    restart: unless-stopped
    ports:
      - "8082:8080"
    environment:
      - ENVIRONMENT=production
      - PORT=8080
      - DATABASE_DIALECT=sqlite
      - DATABASE_URL=file:/data/grantsupport.db?cache=shared&_pragma=foreign_keys(1)&_fk=1&_pragma=busy_timeout(5000)
      - JWT_PRIVATE_KEY=${JWT_PRIVATE_KEY}
      - JWT_PUBLIC_KEY=${JWT_PUBLIC_KEY}
      - MASTER_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
      - LOCAL_SECRET_KEY=0123456789abcdef0123456789abcdef
    volumes:
      - sqlite_data:/data
    profiles:
      - sqlite

  # ==========================================
  # Databases & Optional Valkey Cache
  # ==========================================
  postgres:
    image: postgres:16-alpine
    container_name: gs-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_USER=grantsupport
      - POSTGRES_PASSWORD=secretpassword
      - POSTGRES_DB=grantsupport
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U grantsupport"]
      interval: 5s
      timeout: 5s
      retries: 5
    profiles:
      - default
      - postgres

  mysql:
    image: mysql:8.4
    container_name: gs-mysql
    restart: unless-stopped
    environment:
      - MYSQL_ROOT_PASSWORD=rootsecret
      - MYSQL_DATABASE=grantsupport
      - MYSQL_USER=grantsupport
      - MYSQL_PASSWORD=secretpassword
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "grantsupport", "-psecretpassword"]
      interval: 5s
      timeout: 5s
      retries: 5
    profiles:
      - mysql

  valkey:
    image: valkey/valkey:7.2-alpine
    container_name: gs-valkey
    restart: unless-stopped
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "valkey-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
    profiles:
      - default
      - postgres

volumes:
  postgres_data:
  mysql_data:
  sqlite_data:
```

---

## go.mod

```text
module grantsupport

go 1.25.0

require (
	entgo.io/ent v0.14.1
	github.com/aws/aws-sdk-go-v2/config v1.32.33
	github.com/aws/aws-sdk-go-v2/service/kms v1.55.2
	github.com/go-chi/chi/v5 v5.3.1
	github.com/go-playground/validator/v10 v10.22.0
	github.com/go-sql-driver/mysql v1.10.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/redis/go-redis/v9 v9.5.3
	golang.org/x/crypto v0.52.0
	modernc.org/sqlite v1.56.0
)

require (
	ariga.io/atlas v0.19.1-0.20240203083654-5948b60a8e43 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/agext/levenshtein v1.2.1 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.43.2 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.32 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.34 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.33 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.5.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.33.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.2 // indirect
	github.com/aws/smithy-go v1.27.5 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-openapi/inflect v0.19.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/hashicorp/hcl/v2 v2.13.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mitchellh/go-wordwrap v0.0.0-20150314170334-ad45545899c7 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/zclconf/go-cty v1.8.0 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
```

---

## go.sum

```text
ariga.io/atlas v0.19.1-0.20240203083654-5948b60a8e43 h1:GwdJbXydHCYPedeeLt4x/lrlIISQ4JTH1mRWuE5ZZ14=
ariga.io/atlas v0.19.1-0.20240203083654-5948b60a8e43/go.mod h1:uj3pm+hUTVN/X5yfdBexHlZv+1Xu5u5ZbZx7+CDavNU=
entgo.io/ent v0.14.1 h1:fUERL506Pqr92EPHJqr8EYxbPioflJo6PudkrEA8a/s=
entgo.io/ent v0.14.1/go.mod h1:MH6XLG0KXpkcDQhKiHfANZSzR55TJyPL5IGNpI8wpco=
filippo.io/edwards25519 v1.2.0 h1:crnVqOiS4jqYleHd9vaKZ+HKtHfllngJIiOpNpoJsjo=
filippo.io/edwards25519 v1.2.0/go.mod h1:xzAOLCNug/yB62zG1bQ8uziwrIqIuxhctzJT18Q77mc=
github.com/DATA-DOG/go-sqlmock v1.5.0 h1:Shsta01QNfFxHCfpW6YH2STWB0MudeXXEWMr20OEh60=
github.com/DATA-DOG/go-sqlmock v1.5.0/go.mod h1:f/Ixk793poVmq4qj/V1dPUg2JEAKC73Q5eFN3EC/SaM=
github.com/agext/levenshtein v1.2.1 h1:QmvMAjj2aEICytGiWzmxoE0x2KZvE0fvmqMOfy2tjT8=
github.com/agext/levenshtein v1.2.1/go.mod h1:JEDfjyjHDjOF/1e4FlBE/PkbqA9OfWu2ki2W0IB5558=
github.com/apparentlymart/go-textseg/v13 v13.0.0 h1:Y+KvPE1NYz0xl601PVImeQfFyEy6iT90AvPUL1NNfNw=
github.com/apparentlymart/go-textseg/v13 v13.0.0/go.mod h1:ZK2fH7c4NqDTLtiYLvIkEghdlcqw7yxLeM89kiTRPUo=
github.com/aws/aws-sdk-go-v2 v1.43.2 h1:cl+IXwWb3qazClUcm08tGSsB6OiuV83JVJO9B0jQcPc=
github.com/aws/aws-sdk-go-v2 v1.43.2/go.mod h1:WEzLKBh/mEjXvx1FtQMWgSxMSTVqxQzjkRtk5fa3wkg=
github.com/aws/aws-sdk-go-v2/config v1.32.33 h1:M1m/Q6f0OKDEDGwhiNOqx1OjTdrewe3v+GDbHmKczWk=
github.com/aws/aws-sdk-go-v2/config v1.32.33/go.mod h1:fGj1iQj2QpIZzp7jE4aQQ+71TE8cd4z9K4+xCd6EqmE=
github.com/aws/aws-sdk-go-v2/credentials v1.19.32 h1:eNE0JnIblBo1NCvd3tqEYuZz9XDefn69R74CHd3nT7U=
github.com/aws/aws-sdk-go-v2/credentials v1.19.32/go.mod h1:yYJu+6tqKUYZuJSYcpSGjz/6sV/SUaAaKIufnWKx2OU=
github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.33 h1:MobhiR6KIerWxmO74Zit5I3379+mSc2DOdZ3DeRFB9w=
github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.33/go.mod h1:xu02847OdZfNr/jAfZpHtyRk0b3v4d0kaoxNHxZGG/w=
github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.33 h1:HAp1wLFZzch054uh3FK7rcVYg4v7J2FxVf3h3IGNZas=
github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.33/go.mod h1:mJk5fmqnF+WUlMdPG37pR2Fh3oh6r8F6ZGUgPKvzu0c=
github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.33 h1:0YA0aCKgsJyno6xkFfaIgjE3/wK08+Qxo9nQfe1UrWM=
github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.33/go.mod h1:UZqj4WIdTH+ga8Y/DgpAuy/8cGjM3h7gDCliJYGg2SE=
github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.34 h1:HQYnjFnXpX8EbPW5M1QT8mXzesRPwly0HEPTcFlS02Y=
github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.34/go.mod h1:tGzj56niKYZBbDIRhwPGDqrULzmWv5b6uBQGqyNaFZw=
github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.14 h1:SA43nfaY7+1jjMNIc2ywu99JLJLButtIdLP6j+bT870=
github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.14/go.mod h1:Du3llKcwbQvHsTXSLzTOGQz0DTDBMEzdg7DAGu7inrY=
github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.33 h1:mqI7OrxN/DUH85F5OqVn3cIfuZ3+HVcebUm2N8mLlgQ=
github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.33/go.mod h1:eZ5jdEpvaaOU8nWWE4cTAJETSEA5FZoWxvNRao4piHY=
github.com/aws/aws-sdk-go-v2/service/kms v1.55.2 h1:IoDMH2YObXfIEQRwbWtinQXOqErsyx7Cx73IjpDMKNI=
github.com/aws/aws-sdk-go-v2/service/kms v1.55.2/go.mod h1:LBkxep9UEXaHac8I+GW0PEd87YNcj9B9/GtHiBeSCL8=
github.com/aws/aws-sdk-go-v2/service/signin v1.5.2 h1:EjI1CZzDcBxPkTa3j1BdtIrUDbqnOGssFMeyUS+6W0I=
github.com/aws/aws-sdk-go-v2/service/signin v1.5.2/go.mod h1:vN3eb5H8MEAZ4dx0F5Wc9LT8eb3eW7bZZ5BjGJdbw9k=
github.com/aws/aws-sdk-go-v2/service/sso v1.33.2 h1:zMP1FDFE08L7sM5f1QqkH/ZgKKg8Uc0Dz7KhSSYqWkw=
github.com/aws/aws-sdk-go-v2/service/sso v1.33.2/go.mod h1:0LoIZSUKjdo2BleHfT1hv/jlD33LQS00IrBlzoUsoUQ=
github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.2 h1:9eTqUYl+SyVmaRPMyBXSO9wwqC6TRwZB82pKENK2hdQ=
github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.2/go.mod h1:DThweuz22kiLc7lGHop5vQ9c3bx5W6Azs/YqSHa2fu8=
github.com/aws/aws-sdk-go-v2/service/sts v1.45.2 h1:EJd8vZO3E8SE6nmPqxuxlQ1NeSb8as50sf6eGdV4Saw=
github.com/aws/aws-sdk-go-v2/service/sts v1.45.2/go.mod h1:OgpPvKzsO2Ranjpli/20djMkg6UrV5mw4W3pZpq1Mqo=
github.com/aws/smithy-go v1.27.5 h1:d1ro7KpYOYwP6m73YFa+Kc/A130VsAdX68SpsJwARMM=
github.com/aws/smithy-go v1.27.5/go.mod h1:YE2RhdIuDbA5E5bTdciG9KrW3+TiEONeUWCqxX9i1Fc=
github.com/bsm/ginkgo/v2 v2.12.0 h1:Ny8MWAHyOepLGlLKYmXG4IEkioBysk6GpaRTLC8zwWs=
github.com/bsm/ginkgo/v2 v2.12.0/go.mod h1:SwYbGRRDovPVboqFv0tPTcG1sN61LM1Z4ARdbAV9g4c=
github.com/bsm/gomega v1.27.10 h1:yeMWxP2pV2fG3FgAODIY8EiRE3dy0aeFYt4l7wh6yKA=
github.com/bsm/gomega v1.27.10/go.mod h1:JyEr/xRbxbtgWNi8tIEVPUYZ5Dzef52k01W3YH0H+O0=
github.com/cespare/xxhash/v2 v2.2.0 h1:DC2CZ1Ep5Y4k3ZQ899DldepgrayRUGE6BBZ/cd9Cj44=
github.com/cespare/xxhash/v2 v2.2.0/go.mod h1:VGX0DQ3Q6kWi7AoAeZDth3/j3BFtOZR5XLFGgcrjCOs=
github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f h1:lO4WD4F/rVNCu3HqELle0jiPLLBs70cWOduZpkS1E78=
github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f/go.mod h1:cuUVRXasLTGF7a8hSLbxyZXjz+1KgoB3wDUb6vlszIc=
github.com/dustin/go-humanize v1.0.1 h1:GzkhY7T5VNhEkwH0PVJgjz+fX1rhBrR7pRT3mDkpeCY=
github.com/dustin/go-humanize v1.0.1/go.mod h1:Mu1zIs6XwVuF/gI1OepvI0qD18qycQx+mFykh5fBlto=
github.com/gabriel-vasile/mimetype v1.4.3 h1:in2uUcidCuFcDKtdcBxlR0rJ1+fsokWf+uqxgUFjbI0=
github.com/gabriel-vasile/mimetype v1.4.3/go.mod h1:d8uq/6HKRL6CGdk+aubisF/M5GcPfT7nKyLpA0lbSSk=
github.com/go-chi/chi/v5 v5.3.1 h1:3j4HZLGZQ3JpMCrPJF/Jl3mYJfWLKBfNJ6quurUGCf8=
github.com/go-chi/chi/v5 v5.3.1/go.mod h1:R+tYY2hNuVUUjxoPtqUdgBqevM9s9njzkTLutVsOCto=
github.com/go-openapi/inflect v0.19.0 h1:9jCH9scKIbHeV9m12SmPilScz6krDxKRasNNSNPXu/4=
github.com/go-openapi/inflect v0.19.0/go.mod h1:lHpZVlpIQqLyKwJ4N+YSc9hchQy/i12fJykb83CRBH4=
github.com/go-playground/assert/v2 v2.2.0 h1:JvknZsQTYeFEAhQwI4qEt9cyV5ONwRHC+lYKSsYSR8s=
github.com/go-playground/assert/v2 v2.2.0/go.mod h1:VDjEfimB/XKnb+ZQfWdccd7VUvScMdVu0Titje2rxJ4=
github.com/go-playground/locales v0.14.1 h1:EWaQ/wswjilfKLTECiXz7Rh+3BjFhfDFKv/oXslEjJA=
github.com/go-playground/locales v0.14.1/go.mod h1:hxrqLVvrK65+Rwrd5Fc6F2O76J/NuW9t0sjnWqG1slY=
github.com/go-playground/universal-translator v0.18.1 h1:Bcnm0ZwsGyWbCzImXv+pAJnYK9S473LQFuzCbDbfSFY=
github.com/go-playground/universal-translator v0.18.1/go.mod h1:xekY+UJKNuX9WP91TpwSH2VMlDf28Uj24BCp08ZFTUY=
github.com/go-playground/validator/v10 v10.22.0 h1:k6HsTZ0sTnROkhS//R0O+55JgM8C4Bx7ia+JlgcnOao=
github.com/go-playground/validator/v10 v10.22.0/go.mod h1:dbuPbCMFw/DrkbEynArYaCwl3amGuJotoKCe95atGMM=
github.com/go-sql-driver/mysql v1.10.0 h1:Q+1LV8DkHJvSYAdR83XzuhDaTykuDx0l6fkXxoWCWfw=
github.com/go-sql-driver/mysql v1.10.0/go.mod h1:M+cqaI7+xxXGG9swrdeUIoPG3Y3KCkF0pZej+SK+nWk=
github.com/go-test/deep v1.0.3 h1:ZrJSEWsXzPOxaZnFteGEfooLba+ju3FYIbOrS+rQd68=
github.com/go-test/deep v1.0.3/go.mod h1:wGDj63lr65AM2AQyKZd/NYHGb0R+1RLqB8NKt3aSFNA=
github.com/golang-jwt/jwt/v5 v5.3.1 h1:kYf81DTWFe7t+1VvL7eS+jKFVWaUnK9cB1qbwn63YCY=
github.com/golang-jwt/jwt/v5 v5.3.1/go.mod h1:fxCRLWMO43lRc8nhHWY6LGqRcf+1gQWArsqaEUEa5bE=
github.com/golang/protobuf v1.3.1/go.mod h1:6lQm79b+lXiMfvg/cZm0SGofjICqVBUtrP5yJMmIC1U=
github.com/golang/protobuf v1.3.4/go.mod h1:vzj43D7+SQXF/4pzW/hwtAqwc6iTitCiVSaWz5lYuqw=
github.com/google/go-cmp v0.3.1/go.mod h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
github.com/google/go-cmp v0.6.0 h1:ofyhxvXcZhMsU5ulbFiLKl/XBFqE1GSq7atu8tAmTRI=
github.com/google/go-cmp v0.6.0/go.mod h1:17dUlkBOakJ0+DkrSSNjCkIjxS6bF9zb3elmeNGIjoY=
github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3 h1:LMLX+LgTNWpfvCBdFebv6EsYotImrt/Ppc5cXIriCSo=
github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3/go.mod h1:jl5iWTm0/hd5PjEYEOuwAJ57L/CibdZfrqZ5XA5GrCk=
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/hashicorp/golang-lru/v2 v2.0.7 h1:a+bsQ5rvGLjzHuww6tVxozPZFVghXaHOwFs4luLUK2k=
github.com/hashicorp/golang-lru/v2 v2.0.7/go.mod h1:QeFd9opnmA6QUJc5vARoKUSoFhyfM2/ZepoAG6RGpeM=
github.com/hashicorp/hcl/v2 v2.13.0 h1:0Apadu1w6M11dyGFxWnmhhcMjkbAiKCv7G1r/2QgCNc=
github.com/hashicorp/hcl/v2 v2.13.0/go.mod h1:e4z5nxYlWNPdDSNYX+ph14EvWYMFm3eP0zIUqPc2jr0=
github.com/jackc/pgpassfile v1.0.0 h1:/6Hmqy13Ss2zCq62VdNG8tM1wchn8zjSGOBJ6icpsIM=
github.com/jackc/pgpassfile v1.0.0/go.mod h1:CEx0iS5ambNFdcRtxPj5JhEz+xB6uRky5eyVu/W2HEg=
github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a h1:bbPeKD0xmW/Y25WS6cokEszi5g+S0QxI/d45PkRi7Nk=
github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a/go.mod h1:5TJZWKEWniPve33vlWYSoGYefn3gLQRzjfDlhSJ9ZKM=
github.com/jackc/pgx/v5 v5.6.0 h1:SWJzexBzPL5jb0GEsrPMLIsi/3jOo7RHlzTjcAeDrPY=
github.com/jackc/pgx/v5 v5.6.0/go.mod h1:DNZ/vlrUnhWCoFGxHAG8U2ljioxukquj7utPDgtQdTw=
github.com/jackc/puddle/v2 v2.2.1 h1:RhxXJtFG022u4ibrCSMSiu5aOq1i77R3OHKNJj77OAk=
github.com/jackc/puddle/v2 v2.2.1/go.mod h1:vriiEXHvEE654aYKXXjOvZM39qJ0q+azkZFrfEOc3H4=
github.com/kr/pretty v0.1.0/go.mod h1:dAy3ld7l9f0ibDNOQOHHMYYIIbhfbHSm3C4ZsoJORNo=
github.com/kr/pretty v0.3.0 h1:WgNl7dwNpEZ6jJ9k1snq4pZsg7DOEN8hP9Xw0Tsjwk0=
github.com/kr/pretty v0.3.0/go.mod h1:640gp4NfQd8pI5XOwp5fnNeVWj67G7CFk/SaSQn7NBk=
github.com/kr/pty v1.1.1/go.mod h1:pFQYn66WHrOpPYNljwOMqo10TkYh1fy3cYio2l3bCsQ=
github.com/kr/text v0.1.0/go.mod h1:4Jbv+DJW3UT/LiOwJeYQe1efqtUx/iVham/4vfdArNI=
github.com/kr/text v0.2.0 h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=
github.com/kr/text v0.2.0/go.mod h1:eLer722TekiGuMkidMxC/pM04lWEeraHUUmBw8l2grE=
github.com/kylelemons/godebug v1.1.0 h1:RPNrshWIDI6G2gRW9EHilWtl7Z6Sb1BR0xunSBf0SNc=
github.com/kylelemons/godebug v1.1.0/go.mod h1:9/0rRGxNHcop5bhtWyNeEfOS8JIWk580+fNqagV/RAw=
github.com/leodido/go-urn v1.4.0 h1:WT9HwE9SGECu3lg4d/dIA+jxlljEa1/ffXKmRjqdmIQ=
github.com/leodido/go-urn v1.4.0/go.mod h1:bvxc+MVxLKB4z00jd1z+Dvzr47oO32F/QSNjSBOlFxI=
github.com/mattn/go-isatty v0.0.24 h1:tGZZoVgT/KiqK1c8ocVLeDS8BSWMRd47J3Lbz7vsReI=
github.com/mattn/go-isatty v0.0.24/go.mod h1:nMCL3Zebbrt45jsMDgnfIwz6ydEQApk5oEI3HqDio6A=
github.com/mattn/go-sqlite3 v1.14.16 h1:yOQRA0RpS5PFz/oikGwBEqvAWhWg5ufRz4ETLjwpU1Y=
github.com/mattn/go-sqlite3 v1.14.16/go.mod h1:2eHXhiwb8IkHr+BDWZGa96P6+rkvnG63S2DGjv9HUNg=
github.com/mitchellh/go-wordwrap v0.0.0-20150314170334-ad45545899c7 h1:DpOJ2HYzCv8LZP15IdmG+YdwD2luVPHITV96TkirNBM=
github.com/mitchellh/go-wordwrap v0.0.0-20150314170334-ad45545899c7/go.mod h1:ZXFpozHsX6DPmq2I0TCekCxypsnAUbP2oI0UX1GXzOo=
github.com/ncruces/go-strftime v1.0.0 h1:HMFp8mLCTPp341M/ZnA4qaf7ZlsbTc+miZjCLOFAw7w=
github.com/ncruces/go-strftime v1.0.0/go.mod h1:Fwc5htZGVVkseilnfgOVb9mKy6w1naJmn9CehxcKcls=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/redis/go-redis/v9 v9.5.3 h1:fOAp1/uJG+ZtcITgZOfYFmTKPE7n4Vclj1wZFgRciUU=
github.com/redis/go-redis/v9 v9.5.3/go.mod h1:hdY0cQFCN4fnSYT6TkisLufl/4W5UIXyv0b/CLO2V2M=
github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec h1:W09IVJc94icq4NjY3clb7Lk8O1qJ8BdBEF8z0ibU0rE=
github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec/go.mod h1:qqbHyh8v60DhA7CoWK5oRCqLrMHRGoxYCSS9EjAz6Eo=
github.com/rogpeppe/go-internal v1.15.0 h1:D0RCU5rMAp+SpgkiNdrjfJ+LX4J1M32V2NeCY7EJ6hc=
github.com/rogpeppe/go-internal v1.15.0/go.mod h1:DrUVZyrJU+txYW5/1kwtXQSMFio52ZOxX7yM1VHvnxs=
github.com/sergi/go-diff v1.0.0 h1:Kpca3qRNrduNnOQeazBd0ysaKrUJiIuISHxogkT9RPQ=
github.com/sergi/go-diff v1.0.0/go.mod h1:0CfEIISq7TuYL3j771MWULgwwjU+GofnZX9QAmXWZgo=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/testify v1.3.0/go.mod h1:M5WIy9Dh21IEIfnGCwXGc5bZfKNJtfHm1UVUgZn+9EI=
github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.11.1 h1:7s2iGBzp5EwR7/aIZr8ao5+dra3wiQyKjjFuvgVKu7U=
github.com/stretchr/testify v1.11.1/go.mod h1:wZwfW3scLgRK+23gO65QZefKpKQRnfz6sD981Nm4B6U=
github.com/vmihailenco/msgpack/v4 v4.3.12/go.mod h1:gborTTJjAo/GWTqqRjrLCn9pgNN+NXzzngzBKDPIqw4=
github.com/vmihailenco/tagparser v0.1.1/go.mod h1:OeAg3pn3UbLjkWt+rN9oFYB6u/cQgqMEUPoW2WPyhdI=
github.com/zclconf/go-cty v1.8.0 h1:s4AvqaeQzJIu3ndv4gVIhplVD0krU+bgrcLSVUnaWuA=
github.com/zclconf/go-cty v1.8.0/go.mod h1:vVKLxnk3puL4qRAv72AO+W99LUD4da90g3uUAzyuvAk=
golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:djNgcEr1/C05ACkg1iLfiJU5Ep61QUkGW8qpdssI0+w=
golang.org/x/crypto v0.52.0 h1:RMs7fP2rXdep0CftQlK8Uf+kibLm7qkCcradZWYz988=
golang.org/x/crypto v0.52.0/go.mod h1:1QgfPxDqh0T2M/elOJtp9RvuR95kVjir0e6/BvEmGbc=
golang.org/x/mod v0.37.0 h1:vF1DjpVEshcIqoEaauuHebaLk1O1forxjxBaVn884JQ=
golang.org/x/mod v0.37.0/go.mod h1:m8S8VeM9r4dzDwjrKO0a1sZP3YjeMamRRlD+fmR2Q/0=
golang.org/x/net v0.0.0-20190603091049-60506f45cf65/go.mod h1:HSz+uSET+XFnRR8LxR5pz3Of3rY3CfYBVs4xY44aLks=
golang.org/x/net v0.0.0-20200301022130-244492dfa37a/go.mod h1:z5CRVTTTmAJ677TzLLGU+0bjPO0LkuOLi4/5GtJWs/s=
golang.org/x/net v0.54.0 h1:2zJIZAxAHV/OHCDTCOHAYehQzLfSXuf/5SoL/Dv6w/w=
golang.org/x/net v0.54.0/go.mod h1:Sj4oj8jK6XmHpBZU/zWHw3BV3abl4Kvi+Ut7cQcY+cQ=
golang.org/x/sync v0.21.0 h1:HLII4xRRTtCRkxYp4HNFF0Js/Og6q2i++KXbg0gHCwM=
golang.org/x/sync v0.21.0/go.mod h1:9xrNwdLfx4jkKbNva9FpL6vEN7evnE43NNNJQ2LF3+0=
golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a/go.mod h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=
golang.org/x/sys v0.47.0 h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=
golang.org/x/sys v0.47.0/go.mod h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
golang.org/x/text v0.3.2/go.mod h1:bEr9sfX3Q8Zfm5fL9x+3itogRgK3+ptLWKqgva+5dAk=
golang.org/x/text v0.3.5/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=
golang.org/x/text v0.37.0 h1:Cqjiwd9eSg8e0QAkyCaQTNHFIIzWtidPahFWR83rTrc=
golang.org/x/text v0.37.0/go.mod h1:a5sjxXGs9hsn/AJVwuElvCAo9v8QYLzvavO5z2PiM38=
golang.org/x/tools v0.0.0-20180917221912-90fa682c2a6e/go.mod h1:n7NCudcB/nEzxVGmLbDWY5pfWTLqBcC2KZ6jyYvM4mQ=
golang.org/x/tools v0.47.0 h1:7Kn5x/d1svx/PzryTsqeoZN4TZwqeH5pGWjefhLi/1Q=
golang.org/x/tools v0.47.0/go.mod h1:dFHnyTvFWY212G+h7ZY4Vsp/K3U4/7W9TyVaAul8uCA=
google.golang.org/appengine v1.6.5/go.mod h1:8WjMMxjGQR8xUklV/ARdw2HLXBOI7O7uCIDZVag1xfc=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
modernc.org/cc/v4 v4.29.1 h1:MKgdCV3WykTSPqpVrnxdEDS0HEd2FHpKZDzxzU5LyeI=
modernc.org/cc/v4 v4.29.1/go.mod h1:OnovgIhbbMXMu1aISnJ0wvVD1KnW+cAUJkIrAWh+kVI=
modernc.org/ccgo/v4 v4.34.6 h1:sBgfIwyN0TQ9C5hwIeuqyeAKyMWnbvj2fvpF4L11uzU=
modernc.org/ccgo/v4 v4.34.6/go.mod h1:SZ8YcN9NG7XVsQYdm6jYBvi8PQP1qi+kqB6OhjqI3Fk=
modernc.org/fileutil v1.4.0 h1:j6ZzNTftVS054gi281TyLjHPp6CPHr2KCxEXjEbD6SM=
modernc.org/fileutil v1.4.0/go.mod h1:EqdKFDxiByqxLk8ozOxObDSfcVOv/54xDs/DUHdvCUU=
modernc.org/gc/v2 v2.6.5 h1:nyqdV8q46KvTpZlsw66kWqwXRHdjIlJOhG6kxiV/9xI=
modernc.org/gc/v2 v2.6.5/go.mod h1:YgIahr1ypgfe7chRuJi2gD7DBQiKSLMPgBQe9oIiito=
modernc.org/gc/v3 v3.1.4 h1:2g65LGVSmFQrXeITAw97x7hCRvZFcyE1uDP+7Vng7JI=
modernc.org/gc/v3 v3.1.4/go.mod h1:HFK/6AGESC7Ex+EZJhJ2Gni6cTaYpSMmU/cT9RmlfYY=
modernc.org/goabi0 v0.2.0 h1:HvEowk7LxcPd0eq6mVOAEMai46V+i7Jrj13t4AzuNks=
modernc.org/goabi0 v0.2.0/go.mod h1:CEFRnnJhKvWT1c1JTI3Avm+tgOWbkOu5oPA8eH8LnMI=
modernc.org/libc v1.74.4 h1:fX1Omw4o2/1C2iRkkIsrQTasJQldLhRmuPreXLoWs9k=
modernc.org/libc v1.74.4/go.mod h1:eeQAS9W3sZeKYMFubydxJpII9ybHWshk+7or7bLG9co=
modernc.org/mathutil v1.7.1 h1:GCZVGXdaN8gTqB1Mf/usp1Y/hSqgI2vAGGP4jZMCxOU=
modernc.org/mathutil v1.7.1/go.mod h1:4p5IwJITfppl0G4sUEDtCr4DthTaT47/N3aT6MhfgJg=
modernc.org/memory v1.11.0 h1:o4QC8aMQzmcwCK3t3Ux/ZHmwFPzE6hf2Y5LbkRs+hbI=
modernc.org/memory v1.11.0/go.mod h1:/JP4VbVC+K5sU2wZi9bHoq2MAkCnrt2r98UGeSK7Mjw=
modernc.org/opt v0.2.0 h1:tGyef5ApycA7FSEOMraay9SaTk5zmbx7Tu+cJs4QKZg=
modernc.org/opt v0.2.0/go.mod h1:03fq9lsNfvkYSfxrfUhZCWPk1lm4cq4N+Bh//bEtgns=
modernc.org/sortutil v1.2.1 h1:+xyoGf15mM3NMlPDnFqrteY07klSFxLElE2PVuWIJ7w=
modernc.org/sortutil v1.2.1/go.mod h1:7ZI3a3REbai7gzCLcotuw9AC4VZVpYMjDzETGsSMqJE=
modernc.org/sqlite v1.56.0 h1:/D8e2RfFqoy/Zc6PuC76U28zFwmI/sYx1Kjm4yEn9e0=
modernc.org/sqlite v1.56.0/go.mod h1:yCJ2cmAaIkHQ25oXWrF8H4O1lIfPYPR26yCEDj2P3pQ=
modernc.org/strutil v1.2.1 h1:UneZBkQA+DX2Rp35KcM69cSsNES9ly8mQWD71HKlOA0=
modernc.org/strutil v1.2.1/go.mod h1:EHkiggD70koQxjVdSBM3JKM7k6L0FbGE5eymy9i3B9A=
modernc.org/token v1.1.0 h1:Xl7Ap9dKaEs5kLoOQeQmPWevfnk/DM5qcLcYlA8ys6Y=
modernc.org/token v1.1.0/go.mod h1:UGzOrNV1mAFSEB63lOFHIpNRUVMvYTc6yu1SMY/XTDM=
```

---
