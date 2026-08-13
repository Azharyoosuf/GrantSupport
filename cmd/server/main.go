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
