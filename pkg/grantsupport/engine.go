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
	config                  *EngineConfig
	baseRepo                *repository.BaseRepository
	grantRepo               *repository.SupportGrantRepository
	auditRepo               *repository.SecurityAuditRepository
	accessRequestRepo       *repository.AccessRequestRepository
	grantService            *service.GrantSupportService
	grantController         *controller.SupportGrantController
	auditService            *service.SecurityAuditService
	auditController         *controller.AuditController
	accessRequestService    *service.AccessRequestService
	accessRequestController *controller.AccessRequestController
	jwksController          *controller.JWKSController
	healthController        *controller.HealthController
	lockStore               ports.LockStore
	replayStore             ports.ReplayStore
	revocationStore         ports.RevocationStore
	rateLimiter             ports.RateLimiterStore
	webhookDispatcher       *webhook.WebhookDispatcher
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
	accessRequestRepo := repository.NewAccessRequestRepository(baseRepo)

	grantService := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
	grantService.SetRevocationStore(revocationStore)
	if webhookDispatcher != nil {
		grantService.SetWebhookDispatcher(webhookDispatcher)
	}

	accessRequestService := service.NewAccessRequestService(baseRepo, accessRequestRepo, grantRepo, auditRepo, lockStore)
	if webhookDispatcher != nil {
		accessRequestService.SetWebhookDispatcher(webhookDispatcher)
	}

	grantController := controller.NewSupportGrantController(grantService)
	auditService := service.NewSecurityAuditService(auditRepo)
	auditController := controller.NewAuditController(auditService)
	accessRequestController := controller.NewAccessRequestController(accessRequestService)
	jwksController := controller.NewJWKSController()
	healthController := controller.NewHealthController(Version, targetSQLDB, cfg.RedisClient)

	return &Engine{
		config:                  cfg,
		baseRepo:                baseRepo,
		grantRepo:               grantRepo,
		auditRepo:               auditRepo,
		accessRequestRepo:       accessRequestRepo,
		grantService:            grantService,
		grantController:         grantController,
		auditService:            auditService,
		auditController:         auditController,
		accessRequestService:    accessRequestService,
		accessRequestController: accessRequestController,
		jwksController:          jwksController,
		healthController:        healthController,
		lockStore:               lockStore,
		replayStore:             replayStore,
		revocationStore:         revocationStore,
		rateLimiter:             rateLimiter,
		webhookDispatcher:       webhookDispatcher,
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

// CreateAccessRequest creates and persists a new pending access request.
func (e *Engine) CreateAccessRequest(ctx context.Context, institutionID, requesterID uuid.UUID, input domain.CreateAccessRequestInput) (*domain.AccessRequest, error) {
	return e.accessRequestService.CreateAccessRequest(ctx, institutionID, requesterID, input)
}

// GetAccessRequest retrieves an access request by ID.
func (e *Engine) GetAccessRequest(ctx context.Context, institutionID, requestID uuid.UUID) (*domain.AccessRequest, error) {
	return e.accessRequestService.GetAccessRequest(ctx, institutionID, requestID)
}

// ListAccessRequests retrieves paginated access requests for an institution.
func (e *Engine) ListAccessRequests(ctx context.Context, institutionID uuid.UUID, status string, requesterID *uuid.UUID, limit, offset int) ([]*domain.AccessRequest, error) {
	return e.accessRequestService.ListAccessRequests(ctx, institutionID, status, requesterID, limit, offset)
}

// ApproveAccessRequest atomically transitions the request to APPROVED, creates a SupportGrant, and logs the audit event.
func (e *Engine) ApproveAccessRequest(ctx context.Context, institutionID, approverID, requestID uuid.UUID, input domain.ApproveAccessRequestInput) (*domain.ApproveAccessRequestResult, error) {
	return e.accessRequestService.ApproveAccessRequest(ctx, institutionID, approverID, requestID, input)
}

// RejectAccessRequest atomically transitions the request to REJECTED and logs the audit event.
func (e *Engine) RejectAccessRequest(ctx context.Context, institutionID, rejecterID, requestID uuid.UUID, input domain.RejectAccessRequestInput) error {
	return e.accessRequestService.RejectAccessRequest(ctx, institutionID, rejecterID, requestID, input)
}

// CancelAccessRequest transitions a pending request to CANCELLED.
func (e *Engine) CancelAccessRequest(ctx context.Context, institutionID, actorID, requestID uuid.UUID, isCallerAdmin bool) error {
	return e.accessRequestService.CancelAccessRequest(ctx, institutionID, actorID, requestID, isCallerAdmin)
}

// HTTPHandler returns a ready-to-mount standard http.Handler / chi.Router with all GrantSupport endpoints.
func (e *Engine) HTTPHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.CorrelationIDMiddleware)

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

	// Authenticated Access Request & Customer Admin Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(e.revocationStore))

		// Access Request Creation (Rate limited to 10 req/min)
		r.With(
			middleware.RequireRoles("SUPPORT_AGENT"),
			middleware.RateLimitMiddleware(e.rateLimiter, 10, 60),
		).Post("/api/v1/access-requests", controller.CatchAsync(e.accessRequestController.CreateAccessRequest))

		// Access Request Queries & Cancellation (Shared: Admin & Agent)
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR", "SUPPORT_AGENT"),
		).Get("/api/v1/access-requests", controller.CatchAsync(e.accessRequestController.ListAccessRequests))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR", "SUPPORT_AGENT"),
		).Get("/api/v1/access-requests/{id}", controller.CatchAsync(e.accessRequestController.GetAccessRequest))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR", "SUPPORT_AGENT"),
		).Post("/api/v1/access-requests/{id}/cancel", controller.CatchAsync(e.accessRequestController.CancelAccessRequest))

		// Customer Admin Access Request Approval & Rejection (Rate limited to 20 req/min)
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
			middleware.RateLimitMiddleware(e.rateLimiter, 20, 60),
		).Post("/api/v1/access-requests/{id}/approve", controller.CatchAsync(e.accessRequestController.ApproveAccessRequest))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
			middleware.RateLimitMiddleware(e.rateLimiter, 20, 60),
		).Post("/api/v1/access-requests/{id}/reject", controller.CatchAsync(e.accessRequestController.RejectAccessRequest))

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
