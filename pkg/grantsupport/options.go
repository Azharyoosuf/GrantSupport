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
	Environment     string
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

// WithEnvironment configures runtime environment mode (e.g., "production", "development", "test").
func WithEnvironment(env string) Option {
	return func(c *EngineConfig) {
		c.Environment = env
	}
}
