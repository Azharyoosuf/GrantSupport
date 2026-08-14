package grantsupport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"grantsupport/ent"
	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/ratelimit"
	"grantsupport/pkg/adapters/replay"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/config"
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
			if err := repository.CreateCapabilityTables(migrateCtx, cfg.SQLDB, cfg.Dialect); err != nil {
				return nil, fmt.Errorf("failed to create capability tables: %w", err)
			}
		} else if baseRepo.SQLDB != nil {
			if err := repository.CreateCapabilityTables(migrateCtx, baseRepo.SQLDB, baseRepo.Dialect); err != nil {
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
			isProd := cfg.Environment == "production" || os.Getenv("GO_ENV") == "production"
			if !isProd && config.AppConfig != nil && config.AppConfig.Environment == "production" {
				isProd = true
			}
			if isProd {
				return nil, fmt.Errorf("PRODUCTION_JWT_KEYS_REQUIRED: RSA JWT keys (JWT_PRIVATE_KEY, JWT_PUBLIC_KEY) are required in production: %w", err)
			}
			// Generate test keypair fallback (development/test only)
			if err := security.SetupTestRSAKeys(); err != nil {
				return nil, fmt.Errorf("failed to initialize transient RSA JWT keys: %w", err)
			}
		}
	}

	// 4. Initialize Capability Stores (Default to SQL or In-Memory adapters if omitted)
	targetSQLDB := cfg.SQLDB
	targetDialect := cfg.Dialect
	if targetSQLDB == nil && baseRepo.SQLDB != nil {
		targetSQLDB = baseRepo.SQLDB
		targetDialect = baseRepo.Dialect
	}

	lockStore := cfg.LockStore
	if lockStore == nil {
		if targetSQLDB != nil {
			lockStore = lock.NewSQLLockStore(targetSQLDB, targetDialect)
		} else {
			lockStore = lock.NewMemoryLockStore()
		}
	}

	replayStore := cfg.ReplayStore
	if replayStore == nil {
		if targetSQLDB != nil {
			replayStore = replay.NewSQLReplayStore(targetSQLDB, targetDialect)
		} else {
			replayStore = replay.NewMemoryReplayStore(1 * time.Minute)
		}
	}

	revocationStore := cfg.RevocationStore
	if revocationStore == nil {
		if targetSQLDB != nil {
			revocationStore = revocation.NewSQLRevocationStore(targetSQLDB, targetDialect)
		}
	}
	if revocationStore == nil {
		return nil, errors.New("REVOCATION_STORE_REQUIRED: A valid RevocationStore or database connection must be configured to ensure session revocation security")
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

	// Public Support Login (Rate limited to 10 attempts per minute per IP)
	r.With(
		middleware.RateLimitMiddleware(e.rateLimiter, 10, 60),
	).Post("/api/v1/auth/support/login", controller.CatchAsync(e.grantController.SupportLogin))

	// Authenticated Admin Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(e.revocationStore))
		r.Use(middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(e.grantController.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(e.grantController.RevokeSupport))
	})

	return r
}

// BulletproofMiddleware returns the 5-layer Ed25519 dual-key authentication middleware.
// This is an opt-in capability for Go embedders building their own machine-to-machine API routes.
// It is NOT applied to the default HTTPHandler() endpoints (login/grant/revoke), which use simpler
// JWT bearer authentication instead. Callers must build and manage their own keyStore — no key
// persistence or registration API is provided by this package.
func (e *Engine) BulletproofMiddleware(keyStore map[string]*security.APIKeyDetails) func(http.Handler) http.Handler {
	return middleware.BulletproofAuthMiddleware(e.replayStore, keyStore)
}

// AuthMiddleware returns the JWT bearer authentication middleware with revocation checks.
func (e *Engine) AuthMiddleware() func(http.Handler) http.Handler {
	return middleware.NewAuthMiddleware(e.revocationStore)
}

// Close gracefully releases engine resources and drains in-flight webhooks. Does NOT close caller-provided *sql.DB.
func (e *Engine) Close() error {
	if e.webhookDispatcher != nil {
		drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = e.webhookDispatcher.Close(drainCtx)
		cancel()
	}

	if memReplay, ok := e.replayStore.(*replay.MemoryReplayStore); ok {
		memReplay.Close()
	}

	if e.config.OwnsDB && e.baseRepo != nil && e.baseRepo.SQLDB != nil {
		return e.baseRepo.SQLDB.Close()
	}

	return nil
}
