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
	"github.com/redis/go-redis/v9"
	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/ratelimit"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/cache"
	"grantsupport/pkg/config"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/observability"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
	"grantsupport/pkg/webhook"
	_ "modernc.org/sqlite"
)

func main() {
	slog.Info("Starting GrantSupport Engine...", slog.String("version", grantsupport.Version))

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
		if cfg.Environment == "production" {
			slog.Error("FATAL: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required in production. Exiting.", slog.String("error", err.Error()))
			os.Exit(1)
		}
		slog.Warn("RSA JWT keys not found, generating transient keypair (development only — NOT safe for production)...")
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

	// Apply configured database connection pool settings to prevent connection starvation and resource leaks
	sqlDB.SetMaxOpenConns(cfg.DBMaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.DBMaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.DBConnMaxLifetimeMinutes) * time.Minute)
	sqlDB.SetConnMaxIdleTime(time.Duration(cfg.DBConnMaxIdleTimeMinutes) * time.Minute)

	// Verify database connectivity (Fail fast on startup if database is unreachable)
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		slog.Error("FATAL: Failed to establish database connection on startup", slog.String("dialect", dialectName), slog.String("error", err.Error()))
		os.Exit(1)
	}

	baseRepo := repository.NewBaseRepositoryWithDB(sqlDB, dialectName)
	dbClient := baseRepo.MasterClient
	defer dbClient.Close()

	if cfg.AutoMigrate {
		slog.Info("Running development database auto-migration...")
		if err := dbClient.Schema.Create(context.Background()); err != nil {
			slog.Error("Failed to auto-migrate database schema", slog.String("error", err.Error()))
			os.Exit(1)
		}
		if err := repository.CreateCapabilityTables(context.Background(), sqlDB, dialectName); err != nil {
			slog.Error("Failed to auto-migrate capability tables", slog.String("error", err.Error()))
			os.Exit(1)
		}
	} else {
		slog.Info("Database auto-migration disabled (authoritative versioned SQL migrations enforced)")
	}

	// Initialize Capability Adapters (Redis if configured, else SQL/Memory Stores)
	var lockStore ports.LockStore
	var revocationStore ports.RevocationStore
	var rateLimiter ports.RateLimiterStore
	var redisClient *redis.Client

	if cfg.ValkeyCacheURL != "" {
		valkeyClient, err := cache.NewValkeyClient(cfg.ValkeyCacheURL)
		if err != nil {
			slog.Warn("Valkey connection bypass (running with SQL/Memory lock, revocation & rate limiting)", slog.String("error", err.Error()))
			lockStore = lock.NewSQLLockStore(sqlDB, dialectName)
			revocationStore = revocation.NewSQLRevocationStore(sqlDB, dialectName)
			rateLimiter = ratelimit.NewMemoryRateLimiter()
		} else {
			redisClient = valkeyClient.Client
			lockStore = lock.NewRedisLockStore(valkeyClient.Client)
			revocationStore = revocation.NewRedisRevocationStore(valkeyClient.Client)
			rateLimiter = ratelimit.NewRedisRateLimiter(valkeyClient.Client)
			slog.Info("Valkey distributed cache, locking & rate limiting initialized successfully")
		}
	} else {
		lockStore = lock.NewSQLLockStore(sqlDB, dialectName)
		revocationStore = revocation.NewSQLRevocationStore(sqlDB, dialectName)
		rateLimiter = ratelimit.NewMemoryRateLimiter()
	}

	// Initialize Repositories & Services (Standalone single-tenant / dedicated deployment)
	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	auditRepo.SetLockStore(lockStore)
	accessRequestRepo := repository.NewAccessRequestRepository(baseRepo)

	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)
	grantService.SetRevocationStore(revocationStore)

	var webhookDispatcher *webhook.WebhookDispatcher
	if cfg.WebhookURL != "" {
		if cfg.WebhookSecret == "" {
			slog.Warn("Webhook URL configured without WEBHOOK_SECRET: webhook delivery disabled (unsigned webhooks are prohibited)")
		} else {
			webhookDispatcher = webhook.NewWebhookDispatcher(cfg.WebhookURL, cfg.WebhookSecret)
			grantService.SetWebhookDispatcher(webhookDispatcher)
			slog.Info("Webhook dispatcher initialized", slog.String("url", cfg.WebhookURL))
		}
	}

	accessRequestService := service.NewAccessRequestService(baseRepo, accessRequestRepo, supportGrantRepo, auditRepo, lockStore)
	if webhookDispatcher != nil {
		accessRequestService.SetWebhookDispatcher(webhookDispatcher)
	}

	grantController := controller.NewSupportGrantController(grantService)
	auditService := service.NewSecurityAuditService(auditRepo)
	auditController := controller.NewAuditController(auditService)
	accessRequestController := controller.NewAccessRequestController(accessRequestService)
	jwksController := controller.NewJWKSController()
	healthController := controller.NewHealthController(grantsupport.Version, sqlDB, redisClient)

	// Router Setup
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.CorrelationIDMiddleware)
	r.Use(middleware.SecurityHeadersMiddleware)

	// Public Health & Readiness Probes
	r.Get("/health", controller.CatchAsync(healthController.Live))
	r.Get("/health/live", controller.CatchAsync(healthController.Live))
	r.Get("/health/ready", controller.CatchAsync(healthController.Ready))

	// Prometheus Metrics Scraper Endpoint
	r.Get("/metrics", observability.DefaultRegistry.Handler())

	// Public JWKS Endpoint
	r.Get("/.well-known/jwks.json", controller.CatchAsync(jwksController.GetJWKS))

	// Public Support Agent Login Endpoint (Rate limited to 10 attempts per minute per IP)
	r.With(
		middleware.RateLimitMiddleware(rateLimiter, 10, 60),
	).Post("/api/v1/auth/support/login", controller.CatchAsync(grantController.SupportLogin))

	// Authenticated Access Request & Customer Admin Endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(revocationStore))

		// Access Request Creation (Rate limited to 10 req/min)
		r.With(
			middleware.RequireRoles("SUPPORT_AGENT"),
			middleware.RateLimitMiddleware(rateLimiter, 10, 60),
		).Post("/api/v1/access-requests", controller.CatchAsync(accessRequestController.CreateAccessRequest))

		// Access Request Queries & Cancellation (Shared: Admin & Agent)
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR", "SUPPORT_AGENT"),
		).Get("/api/v1/access-requests", controller.CatchAsync(accessRequestController.ListAccessRequests))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR", "SUPPORT_AGENT"),
		).Get("/api/v1/access-requests/{id}", controller.CatchAsync(accessRequestController.GetAccessRequest))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR", "SUPPORT_AGENT"),
		).Post("/api/v1/access-requests/{id}/cancel", controller.CatchAsync(accessRequestController.CancelAccessRequest))

		// Customer Admin Access Request Approval & Rejection (Rate limited to 20 req/min)
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
			middleware.RateLimitMiddleware(rateLimiter, 20, 60),
		).Post("/api/v1/access-requests/{id}/approve", controller.CatchAsync(accessRequestController.ApproveAccessRequest))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
			middleware.RateLimitMiddleware(rateLimiter, 20, 60),
		).Post("/api/v1/access-requests/{id}/reject", controller.CatchAsync(accessRequestController.RejectAccessRequest))

		// Customer Admin Direct Grant Endpoints
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
			middleware.RateLimitMiddleware(rateLimiter, 20, 60),
		).Post("/api/v1/auth/support/grant", controller.CatchAsync(grantController.GrantSupport))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
			middleware.RateLimitMiddleware(rateLimiter, 10, 60),
		).Post("/api/v1/auth/support/revoke", controller.CatchAsync(grantController.RevokeSupport))

		// Active Session Management
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
		).Get("/api/v1/auth/support/sessions", controller.CatchAsync(grantController.GetActiveSessions))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
		).Delete("/api/v1/auth/support/sessions/{grantId}", controller.CatchAsync(grantController.TerminateSession))

		// Cryptographic Audit Ledger APIs
		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
		).Get("/api/v1/audit/events", controller.CatchAsync(auditController.GetAuditEvents))

		r.With(
			middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER", "OPERATOR"),
		).Post("/api/v1/audit/verify", controller.CatchAsync(auditController.VerifyAuditChain))
	})

	// Authenticated Support Agent Logout Endpoint
	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(revocationStore))
		r.Use(middleware.RequireRoles("SUPPORT_AGENT"))
		r.Post("/api/v1/auth/support/logout", controller.CatchAsync(grantController.SupportLogout))
	})

	port := cfg.Port
	if port == "" {
		port = "8085"
	}

	var serversToShutdown []*http.Server

	if cfg.TLSEnabled {
		slog.Info("Initializing Native TLS termination...", slog.String("cert", cfg.TLSCertFile), slog.String("key", cfg.TLSKeyFile))
		tlsConfig, err := security.NewServerTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			slog.Error("FATAL: Failed to load TLS configuration. Exiting (Fail Startup).", slog.String("error", err.Error()))
			os.Exit(1)
		}

		httpsPort := cfg.HTTPSPort
		if httpsPort == "" {
			httpsPort = "8443"
		}

		httpsServer := &http.Server{
			Addr:              fmt.Sprintf(":%s", httpsPort),
			Handler:           r,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		serversToShutdown = append(serversToShutdown, httpsServer)

		go func() {
			slog.Info("GrantSupport HTTPS Server listening for traffic", slog.String("port", httpsPort), slog.String("min_tls", "1.2"), slog.Bool("http2", true))
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTPS server failed", slog.String("error", err.Error()))
			}
		}()

		// Optional HTTP to HTTPS redirect listener
		if cfg.HTTPToHTTPSRedirect {
			httpRedirectServer := &http.Server{
				Addr:              fmt.Sprintf(":%s", port),
				Handler:           middleware.HTTPToHTTPSRedirectHandler(httpsPort),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
				IdleTimeout:       30 * time.Second,
			}
			serversToShutdown = append(serversToShutdown, httpRedirectServer)

			go func() {
				slog.Info("GrantSupport HTTP->HTTPS Redirect Server listening", slog.String("port", port), slog.String("redirect_to_https_port", httpsPort))
				if err := httpRedirectServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					slog.Error("HTTP redirect server failed", slog.String("error", err.Error()))
				}
			}()
		}
	} else {
		// Plaintext HTTP Server (For local dev or reverse proxy termination)
		httpServer := &http.Server{
			Addr:              fmt.Sprintf(":%s", port),
			Handler:           r,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		serversToShutdown = append(serversToShutdown, httpServer)

		go func() {
			slog.Info("GrantSupport HTTP Server listening for traffic (Reverse-Proxy / Dev Mode)", slog.String("port", port))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP server failed", slog.String("error", err.Error()))
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("Shutting down GrantSupport Engine gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range serversToShutdown {
		_ = srv.Shutdown(ctx)
	}
	slog.Info("GrantSupport Engine stopped cleanly.")
}
