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
