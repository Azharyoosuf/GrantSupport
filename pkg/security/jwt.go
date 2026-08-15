package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultPrimaryKID is the default Key ID when none is specified.
const DefaultPrimaryKID = "grantsupport-primary"

// InitJWTKeys loads RSA Asymmetric Keypair for RS256 signing and registers it with the default kid.
func InitJWTKeys(privateKeyPEM, publicKeyPEM []byte) error {
	return InitJWTKeysWithKID(DefaultPrimaryKID, privateKeyPEM, publicKeyPEM)
}

// InitJWTKeysWithKID loads RSA Asymmetric Keypair for RS256 signing and registers it with an explicit Key ID.
func InitJWTKeysWithKID(kid string, privateKeyPEM, publicKeyPEM []byte) error {
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	defaultKeyManager.SetPrimaryKey(kid, privKey, pubKey)
	return nil
}

// LoadJWTKeysFromEnv loads RS256 keys from environment variables or falls back to test keypair.
func LoadJWTKeysFromEnv() error {
	privPEM := []byte(os.Getenv("JWT_PRIVATE_KEY"))
	pubPEM := []byte(os.Getenv("JWT_PUBLIC_KEY"))
	kid := os.Getenv("JWT_KEY_ID")
	if kid == "" {
		kid = DefaultPrimaryKID
	}

	if len(privPEM) == 0 || len(pubPEM) == 0 {
		return errors.New("JWT_KEYS_MISSING: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY environment variables must be configured")
	}

	return InitJWTKeysWithKID(kid, privPEM, pubPEM)
}

// GenerateRSAKeypairPEM generates a new RSA 2048-bit keypair and returns both in PEM encoding.
func GenerateRSAKeypairPEM() ([]byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return privPEM, pubPEM, nil
}

// SetupTestRSAKeys generates and initializes an ephemeral RSA 2048-bit keypair for test suites.
func SetupTestRSAKeys() error {
	privPEM, pubPEM, err := GenerateRSAKeypairPEM()
	if err != nil {
		return err
	}
	return InitJWTKeysWithKID("test-key-1", privPEM, pubPEM)
}

// GetRSAPublicKey returns the primary public key for legacy JWKS rendering.
func GetRSAPublicKey() *rsa.PublicKey {
	keys := defaultKeyManager.GetAllPublicKeys()
	if pubKey, ok := keys[defaultKeyManager.primaryKID]; ok {
		return pubKey
	}
	if defaultKeyManager.legacyPublicKey != nil {
		return defaultKeyManager.legacyPublicKey
	}
	for _, pubKey := range keys {
		return pubKey
	}
	return nil
}

// CustomClaims represents JWT token payload claims.
type CustomClaims struct {
	UserID        string `json:"user_id"`
	InstitutionID string `json:"institution_id"`
	Role          string `json:"role"`
	Scope         string `json:"scope,omitempty"`
	TokenVersion  int    `json:"token_version"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a new signed RS256 access token.
func GenerateJWT(userID, institutionID, role string, duration time.Duration) (string, error) {
	return GenerateJWTWithScope(userID, institutionID, role, "FULL_ACCESS", duration)
}

// GenerateJWTWithScope creates a new signed RS256 access token with explicit scope.
func GenerateJWTWithScope(userID, institutionID, role, scope string, duration time.Duration) (string, error) {
	return GenerateJWTWithVersion(userID, institutionID, role, scope, 1, duration)
}

// GenerateJWTWithExpiresAt creates a new signed RS256 access token with an explicit expiration timestamp and kid header.
func GenerateJWTWithExpiresAt(userID, institutionID, role, scope string, tokenVersion int, expiresAt time.Time) (string, error) {
	kid, privKey, err := defaultKeyManager.GetSigningKey()
	if err != nil {
		// Attempt to load from env if not initialized
		if envErr := LoadJWTKeysFromEnv(); envErr != nil {
			return "", fmt.Errorf("JWT_SIGNING_FAILED: RSA private key not initialized: %w", envErr)
		}
		kid, privKey, err = defaultKeyManager.GetSigningKey()
		if err != nil {
			return "", fmt.Errorf("JWT_SIGNING_FAILED: RSA private key not available: %w", err)
		}
	}

	if scope == "" {
		scope = "FULL_ACCESS"
	}

	now := time.Now().UTC()
	claims := CustomClaims{
		UserID:        userID,
		InstitutionID: institutionID,
		Role:          role,
		Scope:         scope,
		TokenVersion:  tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt.UTC()),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "GrantSupport",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	return token.SignedString(privKey)
}

// GenerateJWTWithVersion creates a new signed RS256 access token with explicit scope and token version.
func GenerateJWTWithVersion(userID, institutionID, role, scope string, tokenVersion int, duration time.Duration) (string, error) {
	return GenerateJWTWithExpiresAt(userID, institutionID, role, scope, tokenVersion, time.Now().Add(duration))
}

// VerifyJWT parses and verifies a signed RS256 JWT token string using strict key selection.
// If the token contains an unknown kid, it FAILS CLOSED immediately without falling back to any other key.
func VerifyJWT(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		var kidStr string
		if kidVal, ok := t.Header["kid"]; ok && kidVal != nil {
			if str, isStr := kidVal.(string); isStr {
				kidStr = str
			}
		}

		pubKey, err := defaultKeyManager.GetVerificationKey(kidStr)
		if err != nil {
			// If not initialized, attempt loading from env once
			if errors.Is(err, ErrKeyNotFound) {
				if loadErr := LoadJWTKeysFromEnv(); loadErr == nil {
					return defaultKeyManager.GetVerificationKey(kidStr)
				}
			}
			return nil, err
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
