package security

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrUnknownKeyID indicates that the requested key ID ('kid') is not recognized or trusted.
	ErrUnknownKeyID = errors.New("UNKNOWN_KID: The specified key ID is not trusted or recognized")
	// ErrKeyNotFound indicates that no active signing or verification key is available.
	ErrKeyNotFound = errors.New("KEY_NOT_FOUND: No signing or verification key available")
)

// KeyManager manages asymmetric RSA signing and verification keys with Key ID ('kid') tracking.
// It enforces Strict Key Selection: tokens containing an unknown 'kid' fail closed immediately.
type KeyManager struct {
	mu                sync.RWMutex
	primaryKID        string
	primaryPrivateKey *rsa.PrivateKey
	trustedPublicKeys map[string]*rsa.PublicKey
	legacyPublicKey   *rsa.PublicKey
}

// defaultKeyManager is the global package KeyManager instance.
var defaultKeyManager = NewKeyManager()

// NewKeyManager constructs an initialized KeyManager.
func NewKeyManager() *KeyManager {
	return &KeyManager{
		trustedPublicKeys: make(map[string]*rsa.PublicKey),
	}
}

// GetDefaultKeyManager returns the global singleton KeyManager instance.
func GetDefaultKeyManager() *KeyManager {
	return defaultKeyManager
}

// SetPrimaryKey configures the active primary signing keypair and associates it with a Key ID (kid).
func (km *KeyManager) SetPrimaryKey(kid string, privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.primaryKID = kid
	km.primaryPrivateKey = privKey
	if kid != "" && pubKey != nil {
		km.trustedPublicKeys[kid] = pubKey
	}
	if km.legacyPublicKey == nil && pubKey != nil {
		km.legacyPublicKey = pubKey
	}
}

// AddTransitionalPublicKey registers a trusted public key for historical token verification during key rollover.
func (km *KeyManager) AddTransitionalPublicKey(kid string, pubKey *rsa.PublicKey) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if kid != "" && pubKey != nil {
		km.trustedPublicKeys[kid] = pubKey
	}
}

// RemoveTransitionalPublicKey unregisters a transitional public key once its grace period ends.
func (km *KeyManager) RemoveTransitionalPublicKey(kid string) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if kid != km.primaryKID {
		delete(km.trustedPublicKeys, kid)
	}
}

// SetLegacyPublicKey configures the fallback public key used when a legacy JWT omits the 'kid' header.
func (km *KeyManager) SetLegacyPublicKey(pubKey *rsa.PublicKey) {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.legacyPublicKey = pubKey
}

// GetSigningKey returns the active primary signing key and its kid.
func (km *KeyManager) GetSigningKey() (string, *rsa.PrivateKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.primaryPrivateKey == nil {
		return "", nil, ErrKeyNotFound
	}
	return km.primaryKID, km.primaryPrivateKey, nil
}

// GetVerificationKey retrieves the trusted public key corresponding to the provided kid.
// Strict Key Selection Rules:
// 1. If kid is non-empty, it MUST match a registered trusted key.
// 2. Unknown kid returns ErrUnknownKeyID immediately (FAIL CLOSED - NEVER FALLS BACK).
// 3. If kid is empty, it returns the configured legacyPublicKey for backwards compatibility.
func (km *KeyManager) GetVerificationKey(kid string) (*rsa.PublicKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if kid != "" {
		pubKey, ok := km.trustedPublicKeys[kid]
		if !ok || pubKey == nil {
			return nil, fmt.Errorf("%w: kid '%s'", ErrUnknownKeyID, kid)
		}
		return pubKey, nil
	}

	// Legacy token without kid header
	if km.legacyPublicKey != nil {
		return km.legacyPublicKey, nil
	}

	return nil, ErrKeyNotFound
}

// GetAllPublicKeys returns a snapshot map of all currently trusted public keys (kid -> *rsa.PublicKey) for JWKS rendering.
func (km *KeyManager) GetAllPublicKeys() map[string]*rsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()

	res := make(map[string]*rsa.PublicKey, len(km.trustedPublicKeys))
	for k, v := range km.trustedPublicKeys {
		res[k] = v
	}
	return res
}
