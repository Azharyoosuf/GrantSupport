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
