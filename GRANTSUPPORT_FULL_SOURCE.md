# GrantSupport Full Source Code Export

- **Export Date**: 2026-08-12
- **Git Commit**: 7015cb2f435b4f823747064e0cb0371c949ba756

---

## Table of Contents

### cmd/
- [cmd/server/main.go](#cmd-server-main-go)

### pkg/
- [pkg/apierrors/rfc7807.go](#pkg-apierrors-rfc7807-go)
- [pkg/apierrors/rfc7807_test.go](#pkg-apierrors-rfc7807-test-go)
- [pkg/cache/valkey.go](#pkg-cache-valkey-go)
- [pkg/config/config.go](#pkg-config-config-go)
- [pkg/context/context.go](#pkg-context-context-go)
- [pkg/controller/auth_dto.go](#pkg-controller-auth-dto-go)
- [pkg/controller/auth_support_controller.go](#pkg-controller-auth-support-controller-go)
- [pkg/controller/base_controller.go](#pkg-controller-base-controller-go)
- [pkg/domain/support_grant.go](#pkg-domain-support-grant-go)
- [pkg/middleware/auth.go](#pkg-middleware-auth-go)
- [pkg/middleware/bulletproof_auth.go](#pkg-middleware-bulletproof-auth-go)
- [pkg/middleware/bulletproof_auth_test.go](#pkg-middleware-bulletproof-auth-test-go)
- [pkg/middleware/correlation.go](#pkg-middleware-correlation-go)
- [pkg/middleware/rbac.go](#pkg-middleware-rbac-go)
- [pkg/repository/base.go](#pkg-repository-base-go)
- [pkg/repository/security_audit_repository.go](#pkg-repository-security-audit-repository-go)
- [pkg/repository/support_grant_repository.go](#pkg-repository-support-grant-repository-go)
- [pkg/resilience/breaker.go](#pkg-resilience-breaker-go)
- [pkg/security/encryption.go](#pkg-security-encryption-go)
- [pkg/security/encryption_test.go](#pkg-security-encryption-test-go)
- [pkg/security/jwt.go](#pkg-security-jwt-go)
- [pkg/security/keys.go](#pkg-security-keys-go)
- [pkg/security/merkle.go](#pkg-security-merkle-go)
- [pkg/security/merkle_test.go](#pkg-security-merkle-test-go)
- [pkg/service/grant_support_service.go](#pkg-service-grant-support-service-go)
- [pkg/service/grant_support_service_test.go](#pkg-service-grant-support-service-test-go)

### ent/schema/
- [ent/schema/auditevent.go](#ent-schema-auditevent-go)
- [ent/schema/supportgrant.go](#ent-schema-supportgrant-go)

### scripts/
- [scripts/extract_grantsupport.py](#scripts-extract-grantsupport-py)

### Root-level files
- [README.md](#readme-md)
- [go.mod](#go-mod)
- [go.sum](#go-sum)

### Not Yet Implemented
- [Not Yet Implemented](#not-yet-implemented)

---

## cmd/server/main.go

`go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	_ "github.com/jackc/pgx/v5/stdlib"
	"grantsupport/ent"
	"grantsupport/pkg/cache"
	"grantsupport/pkg/config"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
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

	// Initialize Ent ORM Database Master Client
	dbClient, err := ent.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to PostgreSQL database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer dbClient.Close()

	if err := dbClient.Schema.Create(context.Background()); err != nil {
		slog.Error("Failed to auto-migrate database schema", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize Valkey Cache Client (Optional)
	var valkeyClient *cache.ValkeyClient
	if cfg.ValkeyCacheURL != "" {
		valkeyClient, err = cache.NewValkeyClient(cfg.ValkeyCacheURL)
		if err != nil {
			slog.Warn("Valkey connection bypass (running without distributed cache)", slog.String("error", err.Error()))
		}
	}

	// Initialize Repositories & Services
	baseRepo := repository.NewBaseRepository(dbClient, nil, nil)
	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)

	grantService := service.NewGrantSupportService(supportGrantRepo, auditRepo, valkeyClient)
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
		r.Use(middleware.NewAuthMiddleware(valkeyClient))
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

`

---

## pkg/apierrors/rfc7807.go

`go
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

`

## pkg/apierrors/rfc7807_test.go

`go
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

`

## pkg/cache/valkey.go

`go
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

`

## pkg/config/config.go

`go
// Package config handles application environment configuration loading.
package config

import (
	"os"
)

// Config holds environment configurations for database, caching, queues, KMS encryption, and server ports.
type Config struct {
	DatabaseURL        string
	ValkeyCacheURL     string
	ValkeyQueueURL     string
	Port               string
	Environment        string
	AWSRegion          string
	EncryptionProvider string
	KmsKeyID           string
	LocalSecretKey     string
	MasterEncryptionKey string
	TrustedProxies     []string
	EnforceStrictIPBinding bool
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
		dbURL = "postgresql://postgres:password@localhost:5434/homp?sslmode=disable"
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
		if dbURL == "postgresql://postgres:password@localhost:5434/homp?sslmode=disable" {
			panic("CRITICAL_SECURITY_ERROR: Unencrypted fallback DATABASE_URL with default password is strictly forbidden in production!")
		}
	}

	cfg := &Config{
		DatabaseURL:        dbURL,
		ValkeyCacheURL:     valkeyCacheURL,
		ValkeyQueueURL:     valkeyQueueURL,
		Port:               port,
		Environment:        env,
		AWSRegion:          awsRegion,
		EncryptionProvider: provider,
		KmsKeyID:           kmsKeyID,
		LocalSecretKey:     localSecretKey,
		MasterEncryptionKey: masterKey,
		TrustedProxies:     []string{"127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		EnforceStrictIPBinding: strictIP,
	}

	AppConfig = cfg
	return cfg, nil
}

`

## pkg/context/context.go

`go
package pkgctx

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const (
	tenantIDKey contextKey = "tenant_id"
	userIDKey   contextKey = "user_id"
	roleKey     contextKey = "user_role"
)

// WithTenant stores institution ID in context.
func WithTenant(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// GetTenant retrieves institution ID from context.
func GetTenant(ctx context.Context) (uuid.UUID, bool) {
	val, ok := ctx.Value(tenantIDKey).(uuid.UUID)
	return val, ok
}

// WithUser stores user ID in context.
func WithUser(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// GetUser retrieves user ID from context.
func GetUser(ctx context.Context) (uuid.UUID, bool) {
	val, ok := ctx.Value(userIDKey).(uuid.UUID)
	return val, ok
}

// WithRole stores user role in context.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleKey, role)
}

// GetRole retrieves user role from context.
func GetRole(ctx context.Context) (string, bool) {
	val, ok := ctx.Value(roleKey).(string)
	return val, ok
}

`

## pkg/controller/auth_dto.go

`go
package controller

// RegisterInstitutionInput captures request payload for institution self-onboarding.
type RegisterInstitutionInput struct {
	Name       string `json:"name" validate:"required,min=3"`
	Domain     string `json:"domain" validate:"required,min=3"`
	AdminEmail string `json:"adminEmail" validate:"required,email"`
	Password   string `json:"password" validate:"required,min=8"`
}

// LoginInput captures authentication credentials.
type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// MfaVerifyInput captures 2FA verification token payload.
type MfaVerifyInput struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Code   string `json:"code" validate:"required,len=6"`
}

// PasswordResetInput captures token and new password for reset.
type PasswordResetInput struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

// ForgotPasswordInput captures email for password reset request.
type ForgotPasswordInput struct {
	Email string `json:"email" validate:"required,email"`
}

// GrantSupportInput captures support delegation duration request.
type GrantSupportInput struct {
	DurationMinutes int `json:"durationMinutes" validate:"gte=1,lte=1440"`
}

// SupportLoginInput captures support token payload.
type SupportLoginInput struct {
	Token string `json:"token" validate:"required"`
}

// PasskeyVerifyRegisterInput captures passkey registration credential payload.
type PasskeyVerifyRegisterInput struct {
	ID           string `json:"id" validate:"required"`
	RawID        string `json:"rawId" validate:"required"`
	Type         string `json:"type" validate:"required"`
	Response     any    `json:"response"`
	Mock         bool   `json:"mock"`
	CredentialID string `json:"credentialId"`
	PublicKey    string `json:"publicKey"`
}

// PasskeyLoginOptionsInput captures passkey login options request payload.
type PasskeyLoginOptionsInput struct {
	Email string `json:"email" validate:"required,email"`
}

// PasskeyLoginVerifyInput captures passkey assertion verification payload.
type PasskeyLoginVerifyInput struct {
	Email     string `json:"email" validate:"required,email"`
	Assertion any    `json:"assertion"`
}

// VerifyMfaInput captures MFA verification payload.
type VerifyMfaInput struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Code   string `json:"code" validate:"required"`
}

// CompleteMfaInput captures MFA completion payload.
type CompleteMfaInput struct {
	Code string `json:"code" validate:"required"`
}

// AcceptInviteInput captures invitation acceptance payload.
type AcceptInviteInput struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}


`

## pkg/controller/auth_support_controller.go

`go
package controller

import (
	"net/http"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
)

// GrantSupport generates a temporary platform owner support audit token.
// POST /api/v1/auth/support/grant
func (c *AuthController) GrantSupport(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	input, err := DecodeAndValidate[GrantSupportInput](r)
	if err != nil {
		return err
	}

	token, err := c.authService.CreateSupportGrant(r.Context(), tenant.InstitutionID, tenant.UserID, input.DurationMinutes)
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

// SupportLogin authenticates a delegated platform auditor using a support token.
// POST /api/v1/auth/support/login
func (c *AuthController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}

	var callerID uuid.UUID
	if tenant, ok := pkgctx.GetTenant(r.Context()); ok && tenant != nil {
		callerID = tenant.UserID
	}

	user, instID, jwtToken, err := c.authService.SupportLogin(r.Context(), input.Token, callerID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Delegated support login successful.",
		"access_token": jwtToken,
		"data": map[string]any{
			"user":           user,
			"institution_id": instID,
			"access_token":   jwtToken,
		},
	})
	return nil
}

// RevokeSupport revokes all active support delegations.
// POST /api/v1/auth/support/revoke
func (c *AuthController) RevokeSupport(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	if err := c.authService.RevokeSupportGrant(r.Context(), tenant.InstitutionID, tenant.UserID); err != nil {
		return NewAppError(http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "All support delegations revoked successfully.",
	})
	return nil
}

// LogoutAll revokes all active sessions for a user across all devices.
// POST /api/v1/auth/logout-all
func (c *AuthController) LogoutAll(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	if err := c.authService.RevokeAllSessions(r.Context(), tenant.UserID, tenant.InstitutionID); err != nil {
		return NewAppError(http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Logged out from all devices.",
	})
	return nil
}

`

## pkg/controller/base_controller.go

`go
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
		"type":     "https://tenantpro.io/errors/" + strings.ToLower(code),
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

`

## pkg/domain/support_grant.go

`go
package domain

import (
	"time"

	"github.com/google/uuid"
)

type CreateSupportGrantInput struct {
	InstitutionID uuid.UUID `json:"institution_id"`
	GrantedByID   uuid.UUID `json:"granted_by_id"`
	TokenHash     string    `json:"token_hash"`
	ExpiresAt     time.Time `json:"expires_at"`
}

`

## pkg/middleware/auth.go

`go
package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"grantsupport/pkg/cache"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/security"
)

// AuthMiddleware inspects Authorization headers (Bearer JWT) or 5-Layer Dual-Key headers (X-API-KEY-ID) and injects Tenant Context into request context.
func AuthMiddleware(next http.Handler) http.Handler {
	return NewAuthMiddleware(nil)(next)
}

// NewAuthMiddleware constructs a JWT authentication middleware with optional Valkey token version revocation check.
func NewAuthMiddleware(valkey *cache.ValkeyClient) func(http.Handler) http.Handler {
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

			// TokenVersion revocation check against Valkey security cache
			if valkey != nil && valkey.Client != nil {
				cacheKey := fmt.Sprintf("cache:%s:user:security:%s", claims.InstitutionID, claims.UserID)
				cachedVersion, err := valkey.Client.Get(r.Context(), cacheKey).Int()
				if err == nil && cachedVersion > claims.TokenVersion {
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

`

## pkg/middleware/bulletproof_auth.go

`go
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
	"grantsupport/pkg/cache"
	"grantsupport/pkg/config"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
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
func BulletproofAuthMiddleware(valkeyClient *cache.ValkeyClient, keyStore map[string]*security.APIKeyDetails) func(http.Handler) http.Handler {
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

			// Layer 3: Valkey Nonce Replay Check (Fail-Closed)
			if valkeyClient == nil || valkeyClient.Client == nil {
				controller.WriteRFC7807Error(w, http.StatusServiceUnavailable, "SECURITY_CACHE_UNAVAILABLE", "Valkey security cache is required for replay attack protection")
				return
			}

			nonceKey := fmt.Sprintf("nonce:%s:%s", keyID, nonce)
			ttlSeconds := time.Duration(expiresAt-time.Now().Unix()+30) * time.Second
			if ttlSeconds < 10*time.Second {
				ttlSeconds = 10 * time.Second
			}

			// Set Valkey key if Not Exists (SETNX)
			setOk, err := valkeyClient.SetNX(r.Context(), nonceKey, "1", ttlSeconds)
			if err != nil || !setOk {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "REPLAY_ATTACK_DETECTED", "Duplicate request nonce detected (replay attack blocked)")
				return
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
			if keyDetails.InstitutionID != "" {
				instUUID, err := uuid.Parse(keyDetails.InstitutionID)
				if err == nil {
					tenantData := &pkgctx.TenantData{
						InstitutionID: instUUID,
						Role:          "API_SERVICE",
					}
					ctx = pkgctx.WithTenant(ctx, tenantData)
				}
			}

			bctx := &BulletproofSecurityContext{
				KeyID:         keyID,
				InstitutionID: keyDetails.InstitutionID,
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

`

## pkg/middleware/bulletproof_auth_test.go

`go
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

	"grantsupport/pkg/cache"
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
			InstitutionID:   "11111111-1111-1111-1111-111111111111",
			PublicKeyBase64: kp.PublicKeyBase64,
			WhitelistedIPs:  []string{"127.0.0.1"},
			IsActive:        true,
		},
	}

	// 3. Initialize Valkey client (if available)
	valkeyClient, _ := cache.NewValkeyClient("redis://127.0.0.1:6379")

	// 4. Instantiate Bulletproof Auth Middleware
	mw := middleware.BulletproofAuthMiddleware(valkeyClient, keyStore)
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

`

## pkg/middleware/correlation.go

`go
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

`

## pkg/middleware/rbac.go

`go
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

`

## pkg/repository/base.go

`go
package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"grantsupport/ent"

	pkgctx "grantsupport/pkg/context"
	pkgdb "grantsupport/pkg/database"
)

// BaseRepository encapsulates shared connection managers and database wrappers.
type BaseRepository struct {
	MasterClient  *ent.Client
	TenantConnMgr *pkgdb.TenantConnectionManager
	PgxPool       *pgxpool.Pool
	Valkey        *redis.Client
}

// NewBaseRepository creates a new BaseRepository instance.
func NewBaseRepository(masterClient *ent.Client, tenantConnMgr *pkgdb.TenantConnectionManager, pgxPool *pgxpool.Pool, valkey *redis.Client) *BaseRepository {
	return &BaseRepository{
		MasterClient:  masterClient,
		TenantConnMgr: tenantConnMgr,
		PgxPool:       pgxPool,
		Valkey:        valkey,
	}
}

// GetClient resolves the correct Ent client for the active tenant context.
func (r *BaseRepository) GetClient(ctx context.Context) (*ent.Client, error) {
	tenant, ok := pkgctx.GetTenant(ctx)
	if !ok || tenant == nil || tenant.InstitutionID == uuid.Nil || tenant.Role == "PLATFORM_OWNER" {
		// Fallback to MasterClient if context has no tenant or is platform owner
		return r.MasterClient, nil
	}
	return r.TenantConnMgr.GetClient(ctx, tenant.InstitutionID)
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

	// 🛡️ ROW LEVEL SECURITY: Inject active tenant ID into the transaction context.
	// Set the current institution_id parameter in PostgreSQL local session variables.
	tenant, ok := pkgctx.GetTenant(ctx)
	if ok && tenant != nil {
		if tenant.Role == "PLATFORM_OWNER" {
			err = tx.ExecRaw(txCtx, "SET LOCAL app.bypass_rls = 'true'")
			if err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("failed to set RLS bypass context: %w", err)
			}
		} else if tenant.InstitutionID != uuid.Nil {
			instIDStr := tenant.InstitutionID.String()
			if _, parseErr := uuid.Parse(instIDStr); parseErr != nil {
				_ = tx.Rollback()
				return fmt.Errorf("invalid tenant institution ID format for RLS context: %w", parseErr)
			}
			err = tx.ExecRaw(txCtx, "SET LOCAL app.current_institution_id = $1", instIDStr)
			if err != nil {
				// Fallback for drivers that do not support parameter binding on SET LOCAL statements
				err = tx.ExecRaw(txCtx, fmt.Sprintf("SET LOCAL app.current_institution_id = '%s'", instIDStr))
				if err != nil {
					_ = tx.Rollback()
					return fmt.Errorf("failed to set RLS tenant context: %w", err)
				}
			}
		}
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

`

## pkg/repository/security_audit_repository.go

`go
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

// AppendLog records a permanent append-only audit log entry in the database.
func (r *SecurityAuditRepository) AppendLog(ctx context.Context, institutionID, userID uuid.UUID, eventName, description string, tx *ent.Tx) (*AuditLogResult, error) {
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

	now := time.Now()
	event, err := builder.
		SetInstitutionID(institutionID).
		SetCreatedByID(userID).
		SetName(eventName).
		SetDescription(description).
		SetStartDate(now).
		SetEndDate(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return &AuditLogResult{
		ID:        event.ID,
		CreatedAt: event.CreatedAt,
	}, nil
}

`

## pkg/repository/support_grant_repository.go

`go
package repository

import (
	"context"
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

	grant, err := client.SupportGrant.Create().
		SetInstitutionID(data.InstitutionID).
		SetGrantedByID(data.GrantedByID).
		SetTokenHash(data.TokenHash).
		SetExpiresAt(data.ExpiresAt).
		Save(ctx)
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

// MarkGrantAsUsed flags a support grant token as consumed immediately upon first login.
func (r *SupportGrantRepository) MarkGrantAsUsed(ctx context.Context, grantID uuid.UUID) error {
	client, err := r.GetClient(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	_, err = client.SupportGrant.UpdateOneID(grantID).
		SetIsUsed(true).
		SetUsedAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to mark support grant as used: %w", err)
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

`

## pkg/resilience/breaker.go

`go
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

`

## pkg/security/encryption.go

`go
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

`

## pkg/security/encryption_test.go

`go
package security_test

import (
	"context"
	"testing"

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

`

## pkg/security/jwt.go

`go
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
	TokenVersion  int    `json:"token_version"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a new signed RS256 access token.
func GenerateJWT(userID, institutionID, role string, duration time.Duration) (string, error) {
	return GenerateJWTWithVersion(userID, institutionID, role, 1, duration)
}

// GenerateJWTWithVersion creates a new signed RS256 access token with explicit token version.
func GenerateJWTWithVersion(userID, institutionID, role string, tokenVersion int, duration time.Duration) (string, error) {
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

	claims := CustomClaims{
		UserID:        userID,
		InstitutionID: institutionID,
		Role:          role,
		TokenVersion:  tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "TenantPro",
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


`

## pkg/security/keys.go

`go
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

`

## pkg/security/merkle.go

`go
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

`

## pkg/security/merkle_test.go

`go
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

`

## pkg/service/grant_support_service.go

`go
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
	"grantsupport/pkg/cache"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
)

var (
	ErrSupportGrantInvalid = errors.New("SUPPORT_GRANT_INVALID: Invalid or expired support grant token")
	ErrSupportGrantExpired = errors.New("SUPPORT_GRANT_EXPIRED: Support grant token has expired")
	ErrLicenseLimitExceeded = errors.New("LICENSE_LIMIT_EXCEEDED: Maximum agent seat limit reached for your plan tier")
)

type GrantSupportService struct {
	supportGrantRepo *repository.SupportGrantRepository
	auditRepo        *repository.SecurityAuditRepository
	valkey           *cache.ValkeyClient
}

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

// CreateSupportGrant creates a temporary support access token for platform support troubleshooting.
func (s *GrantSupportService) CreateSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int) (string, error) {
	if s.supportGrantRepo == nil {
		return "", errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if durationMinutes <= 0 || durationMinutes > 1440 {
		return "", errors.New("INVALID_DURATION: Support grant duration must be between 1 and 1440 minutes")
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
		InstitutionID: institutionID,
		GrantedByID:   adminUserID,
		TokenHash:     tokenHash,
		ExpiresAt:     expiresAt,
	}

	if s.valkey != nil && s.valkey.LockService != nil {
		lockKey := fmt.Sprintf("lock:grant:%s", institutionID.String())
		err := s.valkey.LockService.WithLock(ctx, lockKey, 10*time.Second, func(txCtx context.Context) error {
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
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_GRANTED", fmt.Sprintf("Support access grant created for %d minutes", durationMinutes), nil)
	}

	return rawToken, nil
}

// SupportLogin authenticates a support agent using a valid support grant token and issues an RS256 JWT access token.
func (s *GrantSupportService) SupportLogin(ctx context.Context, rawToken string, agentUserID uuid.UUID) (uuid.UUID, string, error) {
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
		return uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID, "SUPPORT_ACCESS_LOGGED_IN", fmt.Sprintf("Support login executed by agent %s via active grant", agentUserID.String()), nil)
	}

	jwtToken, err := security.GenerateJWT(
		agentUserID.String(),
		instID.String(),
		"SUPPORT_AGENT",
		4*time.Hour,
	)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to generate support JWT: %w", err)
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

	return nil
}

`

## pkg/service/grant_support_service_test.go

`go
package service_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
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
		svc := service.NewGrantSupportService(nil, nil, nil)
		_, err := svc.CreateSupportGrant(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), 0)
		if err == nil {
			t.Errorf("Expected error for 0 minutes duration")
		}
	})

	t.Run("SupportLogin fails with malformed token", func(t *testing.T) {
		_, _, err := svc.SupportLogin(context.Background(), "invalid-token-without-underscore", uuid.Must(uuid.NewV7()))
		if err == nil {
			t.Errorf("Expected error for malformed token format")
		}
	})
}

`

---

## ent/schema/auditevent.go

`go
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// AuditEvent holds the schema definition for the AuditEvent entity.
type AuditEvent struct {
	ent.Schema
}

// Annotations of the AuditEvent.
func (AuditEvent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "AuditEvent"},
	}
}

// Fields of the AuditEvent.
func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.UUID("institution_id", uuid.UUID{}),
		field.String("name"),
		field.Time("start_date"),
		field.Time("end_date"),
		field.String("description").Optional().Nillable(),
		field.Float("anomaly_multiplier").Default(1.0),
		field.UUID("created_by_id", uuid.UUID{}),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now),
	}
}

// Edges of the AuditEvent.
func (AuditEvent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("institution", Institution.Type).
			Ref("audit_events").
			Unique().
			Field("institution_id").
			Required(),
		edge.From("created_by", User.Type).
			Ref("events_created").
			Unique().
			Field("created_by_id").
			Required(),
	}
}

`

## ent/schema/supportgrant.go

`go
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
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
		entsql.Annotation{Table: "SupportGrant"},
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

// Edges of the SupportGrant.
func (SupportGrant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("institution", Institution.Type).
			Ref("support_grants").
			Unique().
			Field("institution_id").
			Required(),
		edge.From("granted_by", User.Type).
			Ref("support_grants_created").
			Unique().
			Field("granted_by_id").
			Required(),
	}
}

`

---

## scripts/extract_grantsupport.py

`python
#!/usr/bin/env python3
"""
GrantSupport Extraction Script
Copies core GrantSupport files from TenantPro (go-backend) into standalone GrantSupport module.
"""

import os
import shutil
import re

SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "go-backend"))
TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

FILES_TO_COPY = [
    # Schemas
    ("ent/schema/supportgrant.go", "ent/schema/supportgrant.go"),
    ("ent/schema/auditevent.go", "ent/schema/auditevent.go"),
    ("ent/schema/apiusagelog.go", "ent/schema/apiusagelog.go"),
    
    # Domain & Security (Ed25519 + RS256 + 10 Pillars)
    ("pkg/domain/support_grant.go", "pkg/domain/support_grant.go"),
    ("pkg/security/events.go", "pkg/security/events.go"),
    ("pkg/security/jwt.go", "pkg/security/jwt.go"),
    ("pkg/security/keys.go", "pkg/security/keys.go"),
    
    # Repository Layer
    ("pkg/repository/support_grant_repository.go", "pkg/repository/support_grant_repository.go"),
    ("pkg/repository/security_audit_repository.go", "pkg/repository/security_audit_repository.go"),
    ("pkg/repository/api_usage_log_repository.go", "pkg/repository/api_usage_log_repository.go"),
    ("pkg/repository/base.go", "pkg/repository/base.go"),
    
    # Service Layer
    ("pkg/service/auth_service.go", "pkg/service/auth_service.go"),
    
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
    print("Starting GrantSupport Extraction...")
    print(f"Source: {SOURCE_DIR}")
    print(f"Target: {TARGET_DIR}")

    copied_count = 0
    for src_rel, dst_rel in FILES_TO_COPY:
        src_path = os.path.join(SOURCE_DIR, src_rel)
        dst_path = os.path.join(TARGET_DIR, dst_rel)

        if not os.path.exists(src_path):
            print(f"Warning: Source file missing: {src_path}")
            continue

        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.copy2(src_path, dst_path)

        # Fix package imports from tenantpro -> grantsupport
        with open(dst_path, "r", encoding="utf-8") as f:
            content = f.read()

        content = content.replace("tenantpro/", "grantsupport/")
        
        with open(dst_path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"Copied & Updated: {dst_rel}")
        copied_count += 1

    # Create standalone go.mod if not exists
    go_mod_path = os.path.join(TARGET_DIR, "go.mod")
    if not os.path.exists(go_mod_path):
        go_mod_content = """module grantsupport

go 1.22.0
"""
        with open(go_mod_path, "w", encoding="utf-8") as f:
            f.write(go_mod_content)
        print("Created standalone go.mod")

    print(f"\nExtraction Complete! {copied_count} files copied into {TARGET_DIR}")

if __name__ == "__main__":
    main()

`

---

## README.md

`markdown
# GrantSupport — Ephemeral Support Delegation & Audit Engine

> **The Enterprise-Grade Delegated Authorization & Audit Engine for Modern B2B Applications.**
> GrantSupport enables SaaS vendors and self-hosted application developers to receive customer-authorized, time-bound, and fully audited support access without storing passwords, maintaining permanent admin backdoors, or taking on customer PII data liability.

---

## 🌟 Key Architecture & Product Highlights

* **Zero Data-Hosting Liability (Hybrid Control/Data-Plane)**: Customers maintain 100% control over their database, user PII, and infrastructure. GrantSupport runs within their VPC/container while verifying cryptographic license signatures against your JWKS endpoint.
* **Customer-Initiated Delegation**: Support access is never vendor-forced. End-user administrators grant explicit, time-boxed authorization window tokens (e.g. 15m, 1h, 4h).
* **Instant Revocation**: End-users can revoke any active support delegation with a single click.
* **Cryptographic Tamper-Evident Audit Ledger**: Every grant creation, login attempt, and session revocation is recorded in an append-only, SHA-256 hash-chained log protected by database triggers.
* **Cryptographic License & Seat Enforcement**: Enforce seat caps (3, 10, 25, Enterprise) for both Human Support Engineers and Autonomous AI Remediation Agents using Ed25519 asymmetric signatures.

---

## 🏗 System Architecture Overview

```
       ┌─────────────────────────────────────────────────────────────┐
       │             YOUR SAAS HUB (Licensing & JWKS)                 │
       │  - Ed25519 Asymmetric Signatures for License Tokens & APIs  │
       │  - RS256 Keypair for User / Support-Agent Session JWTs      │
       │  - Serves Public Keys via /.well-known/jwks.json             │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
                    Cryptographic License Signature
                                      │
                                      ▼
       ┌─────────────────────────────────────────────────────────────┐
       │            CUSTOMER INFRASTRUCTURE (Docker / VPC)            │
       │                                                             │
       │  ┌──────────────────────┐     ┌──────────────────────────┐  │
       │  │ GrantSupport Core    │ ──► │ Local Database & Valkey   │  │
       │  │ (Go Binary / Container)│     │ (Customer Owned PII/Data)│  │
       │  └──────────────────────┘     └──────────────────────────┘  │
       │                                                             │
       │  1. Verifies License Signature with your Public Key         │
       │  2. Enforces Seat Caps (Human & AI Agents) locally           │
       │  3. Issues Ephemeral Support Tokens & Append-Only Audits     │
       └─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Customer Deployment)

### 1. Docker Compose Setup

Customers deploy GrantSupport alongside their existing PostgreSQL and Valkey/Redis infrastructure using `docker-compose.yml`:

```yaml
version: '3.8'

services:
  grantsupport-core:
    image: your-registry.com/grantsupport-core:v1.0.0
    container_name: grantsupport-core
    ports:
      - "8085:8085"
    environment:
      - PORT=8085
      - DATABASE_URL=postgres://postgres:password@postgres:5432/customer_db?sslmode=disable
      - VALKEY_URL=redis://valkey:6379/0
      - LICENSE_KEY=eyJh... (Signed Ed25519 License Key)
      - JWKS_URL=https://licensing.yourcompany.com/.well-known/jwks.json
    depends_on:
      - postgres
      - valkey

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: customer_db
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"

  valkey:
    image: valkey/valkey:7.2-alpine
    ports:
      - "6379:6379"
```

---

## 🔌 Core API Endpoints

### 1. Issue Delegation Grant (Customer Admin Initiated)
`POST /api/v1/auth/support/grant`
```json
// Headers: Authorization: Bearer <Customer_Admin_JWT>
{
  "duration_minutes": 60,
  "reason": "Investigating invoice discrepancy ticket #4029"
}
```
**Response**:
```json
{
  "success": true,
  "grant_token": "inst_99812_a8b9f10c...",
  "expires_at": "2026-07-30T19:30:00Z"
}
```

### 2. Support Agent Login (Human or AI Agent)
`POST /api/v1/auth/support/login`
```json
{
  "token": "inst_99812_a8b9f10c...",
  "agent_id": "agent_sarah_123"
}
```
**Response**:
```json
{
  "success": true,
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "role": "SUPPORT_AGENT",
  "expires_in": 14400
}
```

### 3. Revoke Delegation Grant (Customer Admin Initiated)
`POST /api/v1/auth/support/revoke`
```json
{
  "success": true,
  "message": "All active support delegation grants revoked immediately."
}
```

---

## 💎 Tier & License Enforcement

GrantSupport enforces tier limits locally inside the customer container without querying your database:

| Feature / Tier | Starter (3 Seats) | Professional (10 Seats) | Business (25 Seats) | Enterprise |
| :--- | :---: | :---: | :---: | :---: |
| **Max Human Agents** | 3 | 10 | 25 | Unlimited |
| **Max AI Remediation Bots** | 1 | 5 | 15 | Custom |
| **Tamper-Evident Ledger** | Yes | Yes | Yes | Yes + S3 Cold Export |
| **Offline Grace Period** | 7 Days | 7 Days | 14 Days | 30 Days / Air-Gapped |

---

## 📄 License & Documentation Index

* 📘 [Architecture Specification](docs/ARCHITECTURE.md) — Deep dive into Control/Data Plane separation and cryptographic design.
* 📗 [Integration Guide](docs/INTEGRATION_GUIDE.md) — Step-by-step developer onboarding and SDK integration guide.
* 📙 [Commercial & Tiering Models](docs/COMMERCIAL_MODELS.md) — Pricing structures, license key generation, and anti-piracy mechanisms.

`

## go.mod

`text
module grantsupport

go 1.25.0

require (
	entgo.io/ent v0.14.1
	github.com/aws/aws-sdk-go-v2/config v1.32.33
	github.com/aws/aws-sdk-go-v2/service/kms v1.55.2
	github.com/go-chi/chi/v5 v5.3.1
	github.com/go-playground/validator/v10 v10.22.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/redis/go-redis/v9 v9.5.3
	golang.org/x/crypto v0.52.0
)

require (
	ariga.io/atlas v0.19.1-0.20240203083654-5948b60a8e43 // indirect
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
	github.com/mitchellh/go-wordwrap v0.0.0-20150314170334-ad45545899c7 // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/zclconf/go-cty v1.8.0 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

`

## go.sum

`text
ariga.io/atlas v0.19.1-0.20240203083654-5948b60a8e43 h1:GwdJbXydHCYPedeeLt4x/lrlIISQ4JTH1mRWuE5ZZ14=
ariga.io/atlas v0.19.1-0.20240203083654-5948b60a8e43/go.mod h1:uj3pm+hUTVN/X5yfdBexHlZv+1Xu5u5ZbZx7+CDavNU=
entgo.io/ent v0.14.1 h1:fUERL506Pqr92EPHJqr8EYxbPioflJo6PudkrEA8a/s=
entgo.io/ent v0.14.1/go.mod h1:MH6XLG0KXpkcDQhKiHfANZSzR55TJyPL5IGNpI8wpco=
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
github.com/go-test/deep v1.0.3 h1:ZrJSEWsXzPOxaZnFteGEfooLba+ju3FYIbOrS+rQd68=
github.com/go-test/deep v1.0.3/go.mod h1:wGDj63lr65AM2AQyKZd/NYHGb0R+1RLqB8NKt3aSFNA=
github.com/golang-jwt/jwt/v5 v5.3.1 h1:kYf81DTWFe7t+1VvL7eS+jKFVWaUnK9cB1qbwn63YCY=
github.com/golang-jwt/jwt/v5 v5.3.1/go.mod h1:fxCRLWMO43lRc8nhHWY6LGqRcf+1gQWArsqaEUEa5bE=
github.com/golang/protobuf v1.3.1/go.mod h1:6lQm79b+lXiMfvg/cZm0SGofjICqVBUtrP5yJMmIC1U=
github.com/golang/protobuf v1.3.4/go.mod h1:vzj43D7+SQXF/4pzW/hwtAqwc6iTitCiVSaWz5lYuqw=
github.com/google/go-cmp v0.3.1/go.mod h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
github.com/google/go-cmp v0.6.0 h1:ofyhxvXcZhMsU5ulbFiLKl/XBFqE1GSq7atu8tAmTRI=
github.com/google/go-cmp v0.6.0/go.mod h1:17dUlkBOakJ0+DkrSSNjCkIjxS6bF9zb3elmeNGIjoY=
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
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
github.com/mattn/go-sqlite3 v1.14.16 h1:yOQRA0RpS5PFz/oikGwBEqvAWhWg5ufRz4ETLjwpU1Y=
github.com/mattn/go-sqlite3 v1.14.16/go.mod h1:2eHXhiwb8IkHr+BDWZGa96P6+rkvnG63S2DGjv9HUNg=
github.com/mitchellh/go-wordwrap v0.0.0-20150314170334-ad45545899c7 h1:DpOJ2HYzCv8LZP15IdmG+YdwD2luVPHITV96TkirNBM=
github.com/mitchellh/go-wordwrap v0.0.0-20150314170334-ad45545899c7/go.mod h1:ZXFpozHsX6DPmq2I0TCekCxypsnAUbP2oI0UX1GXzOo=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/redis/go-redis/v9 v9.5.3 h1:fOAp1/uJG+ZtcITgZOfYFmTKPE7n4Vclj1wZFgRciUU=
github.com/redis/go-redis/v9 v9.5.3/go.mod h1:hdY0cQFCN4fnSYT6TkisLufl/4W5UIXyv0b/CLO2V2M=
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
golang.org/x/mod v0.35.0 h1:Ww1D637e6Pg+Zb2KrWfHQUnH2dQRLBQyAtpr/haaJeM=
golang.org/x/mod v0.35.0/go.mod h1:+GwiRhIInF8wPm+4AoT6L0FA1QWAad3OMdTRx4tFYlU=
golang.org/x/net v0.0.0-20190603091049-60506f45cf65/go.mod h1:HSz+uSET+XFnRR8LxR5pz3Of3rY3CfYBVs4xY44aLks=
golang.org/x/net v0.0.0-20200301022130-244492dfa37a/go.mod h1:z5CRVTTTmAJ677TzLLGU+0bjPO0LkuOLi4/5GtJWs/s=
golang.org/x/net v0.54.0 h1:2zJIZAxAHV/OHCDTCOHAYehQzLfSXuf/5SoL/Dv6w/w=
golang.org/x/net v0.54.0/go.mod h1:Sj4oj8jK6XmHpBZU/zWHw3BV3abl4Kvi+Ut7cQcY+cQ=
golang.org/x/sync v0.20.0 h1:e0PTpb7pjO8GAtTs2dQ6jYa5BWYlMuX047Dco/pItO4=
golang.org/x/sync v0.20.0/go.mod h1:9xrNwdLfx4jkKbNva9FpL6vEN7evnE43NNNJQ2LF3+0=
golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a/go.mod h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=
golang.org/x/sys v0.45.0 h1:dO4czNzziLiiXplLQgBCEpCvXQ3dnkn0SdaZSYdQ+FY=
golang.org/x/sys v0.45.0/go.mod h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
golang.org/x/text v0.3.2/go.mod h1:bEr9sfX3Q8Zfm5fL9x+3itogRgK3+ptLWKqgva+5dAk=
golang.org/x/text v0.3.5/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=
golang.org/x/text v0.37.0 h1:Cqjiwd9eSg8e0QAkyCaQTNHFIIzWtidPahFWR83rTrc=
golang.org/x/text v0.37.0/go.mod h1:a5sjxXGs9hsn/AJVwuElvCAo9v8QYLzvavO5z2PiM38=
golang.org/x/tools v0.0.0-20180917221912-90fa682c2a6e/go.mod h1:n7NCudcB/nEzxVGmLbDWY5pfWTLqBcC2KZ6jyYvM4mQ=
google.golang.org/appengine v1.6.5/go.mod h1:8WjMMxjGQR8xUklV/ARdw2HLXBOI7O7uCIDZVag1xfc=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=

`

---

## Not Yet Implemented

The following files are referenced in system architecture and phase plans, but are not yet implemented in the codebase:

- docker/docker-compose.yml
- ent/schema/institutionwebhook.go
- migrations/mysql/000001_create_grantsupport_tables.sql
- migrations/mysql/000002_add_immutability_triggers.sql
- migrations/mysql/000003_add_hash_chain_check.sql
- migrations/postgres/000001_create_grantsupport_tables.sql
- migrations/postgres/000002_add_immutability_triggers.sql
- migrations/postgres/000003_add_hash_chain_check.sql
- migrations/sqlite/000001_create_grantsupport_tables.sql
- migrations/sqlite/000002_immutability_limitation.md
- migrations/sqlite/000003_add_hash_chain_check.sql
- pkg/encryption/encryptor.go
- pkg/license/manager.go
- pkg/middleware/ratelimit.go
- pkg/repository/webhook_repository.go
- pkg/sdk/sdk.go
- pkg/security/sanitizer.go
- pkg/service/webhook_dispatcher.go
- web/widget/grantsupport.js
