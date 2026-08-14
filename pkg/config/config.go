// Package config handles application environment configuration loading.
package config

import (
	"os"
	"strconv"
	"strings"
)

// Config holds environment configurations for database, caching, queues, KMS encryption, and server ports.
type Config struct {
	DatabaseURL              string
	DatabaseDialect          string
	ValkeyCacheURL           string
	ValkeyQueueURL           string
	Port                     string
	Environment              string
	AWSRegion                string
	EncryptionProvider       string
	KmsKeyID                 string
	LocalSecretKey           string
	MasterEncryptionKey      string
	TrustedProxies           []string
	EnforceStrictIPBinding   bool
	WebhookURL               string
	WebhookSecret            string
	AutoMigrate              bool
	DBMaxOpenConns           int
	DBMaxIdleConns           int
	DBConnMaxLifetimeMinutes int
	DBConnMaxIdleTimeMinutes int
	TLSEnabled               bool
	TLSCertFile              string
	TLSKeyFile               string
	HTTPSPort                string
	HTTPToHTTPSRedirect      bool
	HSTSEnabled              bool
	HSTSMaxAge               int
	HSTSIncludeSubdomains    bool
	HSTSPreload              bool
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

	autoMigrateStr := os.Getenv("AUTO_MIGRATE")
	autoMigrate := false
	if autoMigrateStr == "true" || (autoMigrateStr == "" && env != "production") {
		autoMigrate = true
	}

	maxOpenConns := 50
	if v := os.Getenv("DB_MAX_OPEN_CONNS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			maxOpenConns = parsed
		}
	}

	maxIdleConns := 10
	if v := os.Getenv("DB_MAX_IDLE_CONNS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			maxIdleConns = parsed
		}
	}

	connMaxLifetime := 15
	if v := os.Getenv("DB_CONN_MAX_LIFETIME_MINUTES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			connMaxLifetime = parsed
		}
	}

	connMaxIdleTime := 5
	if v := os.Getenv("DB_CONN_MAX_IDLE_TIME_MINUTES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			connMaxIdleTime = parsed
		}
	}

	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	tlsEnabled := os.Getenv("TLS_ENABLED") == "true" || (tlsCertFile != "" && tlsKeyFile != "")
	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}
	httpToHTTPSRedirect := os.Getenv("HTTP_TO_HTTPS_REDIRECT") == "true"
	hstsEnabled := os.Getenv("HSTS_ENABLED") == "true" || (tlsEnabled && env == "production")
	hstsMaxAge := 31536000
	if v := os.Getenv("HSTS_MAX_AGE"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			hstsMaxAge = parsed
		}
	}
	hstsIncludeSubdomains := os.Getenv("HSTS_INCLUDE_SUBDOMAINS") == "true"
	hstsPreload := os.Getenv("HSTS_PRELOAD") == "true"

	var trustedProxies []string
	if rawProxies := os.Getenv("TRUSTED_PROXIES"); rawProxies != "" {
		for _, p := range strings.Split(rawProxies, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				trustedProxies = append(trustedProxies, trimmed)
			}
		}
	}
	if len(trustedProxies) == 0 {
		// Default to loopback only (127.0.0.1, ::1) to prevent blind trust of private RFC1918 addresses
		trustedProxies = []string{"127.0.0.1", "::1"}
	}

	cfg := &Config{
		DatabaseURL:              dbURL,
		DatabaseDialect:          dbDialect,
		ValkeyCacheURL:           valkeyCacheURL,
		ValkeyQueueURL:           valkeyQueueURL,
		Port:                     port,
		Environment:              env,
		AWSRegion:                awsRegion,
		EncryptionProvider:       provider,
		KmsKeyID:                 kmsKeyID,
		LocalSecretKey:           localSecretKey,
		MasterEncryptionKey:      masterKey,
		TrustedProxies:           trustedProxies,
		EnforceStrictIPBinding:   strictIP,
		WebhookURL:               webhookURL,
		WebhookSecret:            webhookSecret,
		AutoMigrate:              autoMigrate,
		DBMaxOpenConns:           maxOpenConns,
		DBMaxIdleConns:           maxIdleConns,
		DBConnMaxLifetimeMinutes: connMaxLifetime,
		DBConnMaxIdleTimeMinutes: connMaxIdleTime,
		TLSEnabled:               tlsEnabled,
		TLSCertFile:              tlsCertFile,
		TLSKeyFile:               tlsKeyFile,
		HTTPSPort:                httpsPort,
		HTTPToHTTPSRedirect:      httpToHTTPSRedirect,
		HSTSEnabled:              hstsEnabled,
		HSTSMaxAge:               hstsMaxAge,
		HSTSIncludeSubdomains:    hstsIncludeSubdomains,
		HSTSPreload:              hstsPreload,
	}

	AppConfig = cfg
	return cfg, nil
}
