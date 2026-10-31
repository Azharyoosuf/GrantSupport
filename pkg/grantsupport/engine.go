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
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/config"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/observability"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
	"grantsupport/pkg/webhook"
)

// Version defines the current semantic version of GrantSupport.
const Version = "v0.1.0-beta.3"

// Engine is the central embeddable GrantSupport core engine instance.
type Engine struct {
	config            *EngineConfig
	baseRepo          *repository.BaseRepository
	grantRepo         *repository.SupportGrantRepository
	auditRepo         *repository.SecurityAuditRepository
	grantService      *service.GrantSupportService
	grantController   *controller.SupportGrantController
	auditService      *service.SecurityAuditService
	auditController   *controller.AuditController
	jwksController    *controller.JWKSController
	healthController  *controller.HealthController
	lockStore         ports.LockStore
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
		if cfg.RedisClient != nil {
			lockStore = lock.NewRedisLockStore(cfg.RedisClient)
		} else if targetSQLDB != nil {
			lockStore = lock.NewSQLLockStore(targetSQLDB, targetDialect)
		} else {
			lockStore = lock.NewMemoryLockStore()
		}
	}

	revocationStore := cfg.RevocationStore
	if revocationStore == nil {
		if cfg.RedisClient != nil {
			revocationStore = revocation.NewRedisRevocationStore(cfg.RedisClient)
		} else if targetSQLDB != nil {
			revocationStore = revocation.NewSQLRevocationStore(targetSQLDB, targetDialect)
		}
	}
	if revocationStore == nil {
		return nil, errors.New("REVOCATION_STORE_REQUIRED: A valid RevocationStore or database connection must be configured to ensure session revocation security")
	}

	rateLimiter := cfg.RateLimiter
	if rateLimiter == nil {
		if cfg.RedisClient != nil {
			rateLimiter = ratelimit.NewRedisRateLimiter(cfg.RedisClient)
		} else {
			rateLimiter = ratelimit.NewMemoryRateLimiter()
		}
	}

	// 5. Initialize Webhook Dispatcher (only when both URL and secret are configured)
	var webhookDispatcher *webhook.WebhookDispatcher
	if cfg.WebhookURL != "" && cfg.WebhookSecret != "" {
		webhookDispatcher = webhook.NewWebhookDispatcher(cfg.WebhookURL, cfg.WebhookSecret)
	}

	// 6. Assemble Repositories, Services, and Controllers
	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	auditRepo.SetLockStore(lockStore)

	grantService := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
	grantService.SetRevocationStore(revocationStore)
	if webhookDispatcher != nil {
		grantService.SetWebhookDispatcher(webhookDispatcher)
	}

	grantController := controller.NewSupportGrantController(grantService)
	auditService := service.NewSecurityAuditService(auditRepo)
	auditController := controller.NewAuditController(auditService)
	jwksController := controller.NewJWKSController()
	healthController := controller.NewHealthController(Version, targetSQLDB, cfg.RedisClient)

	return &Engine{
		config:            cfg,
		baseRepo:          baseRepo,
		grantRepo:         grantRepo,
		auditRepo:         auditRepo,
		grantService:      grantService,
		grantController:   grantController,
		auditService:      auditService,
		auditController:   auditController,
		jwksController:    jwksController,
		healthController:  healthController,
		lockStore:         lockStore,
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
// If the grant has whitelisted_ips configured, clientIP is validated before consumption.
func (e *Engine) SupportLogin(ctx context.Context, rawToken string, agentUserID uuid.UUID, clientIP ...string) (uuid.UUID, string, error) {
	return e.grantService.SupportLogin(ctx, rawToken, agentUserID, clientIP...)
}

// RevokeSupportGrant invalidates all active support access grants for an institution and terminates active support-agent sessions.
func (e *Engine) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	return e.grantService.RevokeSupportGrant(ctx, institutionID, adminUserID)
}

// SupportLogout voluntarily terminates the authenticated support agent's active session.
func (e *Engine) SupportLogout(ctx context.Context, institutionID, agentUserID uuid.UUID) error {
	return e.grantService.SupportLogout(ctx, institutionID, agentUserID)
}

// GetActiveSessions queries all active redeemed support sessions for an institution.
func (e *Engine) GetActiveSessions(ctx context.Context, institutionID uuid.UUID) ([]*domain.ActiveSession, error) {
	return e.grantService.GetActiveSessions(ctx, institutionID)
}

// TerminateSession terminates a specific active support session by grant ID.
func (e *Engine) TerminateSession(ctx context.Context, institutionID, adminUserID, grantID uuid.UUID) error {
	return e.grantService.TerminateSession(ctx, institutionID, adminUserID, grantID)
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
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.CorrelationIDMiddleware)
	r.Use(middleware.SecurityHeadersMiddleware)

	// Public Health & Readiness Probes
	r.Get("/health", controller.CatchAsync(e.healthController.Live))
	r.Get("/health/live", controller.CatchAsync(e.healthController.Live))
	r.Get("/health/ready", controller.CatchAsync(e.healthController.Ready))

	// Prometheus Metrics Scraper Endpoint
	r.Get("/metrics", observability.DefaultRegistry.Handler())

	// Public JWKS Endpoint
	r.Get("/.well-known/jwks.json", controller.CatchAsync(e.jwksController.GetJWKS))

	// Public Support Login (Rate limited to 10 attempts per minute per IP)
	r.With(
		middleware.RateLimitMiddleware(e.rateLimiter, 10, 60),
	).Post("/api/v1/auth/support/login", controller.CatchAsync(e.grantController.SupportLogin))

	// Authenticated Customer Admin Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(e.revocationStore))

		// Customer Admin Direct Grant Endpoints
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
			middleware.RateLimitMiddleware(e.rateLimiter, 20, 60),
		).Post("/api/v1/auth/support/grant", controller.CatchAsync(e.grantController.GrantSupport))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
			middleware.RateLimitMiddleware(e.rateLimiter, 10, 60),
		).Post("/api/v1/auth/support/revoke", controller.CatchAsync(e.grantController.RevokeSupport))

		// Active Session Management
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
		).Get("/api/v1/auth/support/sessions", controller.CatchAsync(e.grantController.GetActiveSessions))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
		).Delete("/api/v1/auth/support/sessions/{grantId}", controller.CatchAsync(e.grantController.TerminateSession))

		// Cryptographic Audit Ledger APIs
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
		).Get("/api/v1/audit/events", controller.CatchAsync(e.auditController.GetAuditEvents))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
		).Post("/api/v1/audit/verify", controller.CatchAsync(e.auditController.VerifyAuditChain))
	})

	// Authenticated Support Agent Logout Endpoint
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(e.revocationStore))
		r.Use(middleware.RequireRoles("SUPPORT_AGENT"))
		r.Post("/api/v1/auth/support/logout", controller.CatchAsync(e.grantController.SupportLogout))
	})

	return r
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

	if e.config.OwnsDB && e.baseRepo != nil && e.baseRepo.SQLDB != nil {
		return e.baseRepo.SQLDB.Close()
	}

	return nil
}
