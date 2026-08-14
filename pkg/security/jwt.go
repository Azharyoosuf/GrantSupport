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

// GenerateJWTWithVersion creates a new signed RS256 access token with explicit scope and token version.
func GenerateJWTWithVersion(userID, institutionID, role, scope string, tokenVersion int, duration time.Duration) (string, error) {
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

	if scope == "" {
		scope = "FULL_ACCESS"
	}

	claims := CustomClaims{
		UserID:        userID,
		InstitutionID: institutionID,
		Role:          role,
		Scope:         scope,
		TokenVersion:  tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "GrantSupport",
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
