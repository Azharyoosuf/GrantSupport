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
