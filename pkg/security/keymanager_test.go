package security_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"grantsupport/pkg/security"
)

func TestKeyManager_StrictKeySelection(t *testing.T) {
	// Generate Keypair 1
	privPEM1, pubPEM1, err := security.GenerateRSAKeypairPEM()
	if err != nil {
		t.Fatalf("failed to generate keypair 1: %v", err)
	}

	// Generate Keypair 2 (Transitional / Second key)
	privPEM2, pubPEM2, err := security.GenerateRSAKeypairPEM()
	if err != nil {
		t.Fatalf("failed to generate keypair 2: %v", err)
	}

	privKey1, _ := jwt.ParseRSAPrivateKeyFromPEM(privPEM1)
	pubKey1, _ := jwt.ParseRSAPublicKeyFromPEM(pubPEM1)

	privKey2, _ := jwt.ParseRSAPrivateKeyFromPEM(privPEM2)
	pubKey2, _ := jwt.ParseRSAPublicKeyFromPEM(pubPEM2)

	km := security.NewKeyManager()
	km.SetPrimaryKey("key-primary", privKey1, pubKey1)
	km.AddTransitionalPublicKey("key-transitional", pubKey2)

	// 1. Generate token signed with key-primary
	claims1 := security.CustomClaims{
		UserID:        "user-1",
		InstitutionID: "inst-1",
		Role:          "SUPPORT_AGENT",
		TokenVersion:  1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	token1 := jwt.NewWithClaims(jwt.SigningMethodRS256, claims1)
	token1.Header["kid"] = "key-primary"
	signed1, err := token1.SignedString(privKey1)
	if err != nil {
		t.Fatalf("failed to sign token 1: %v", err)
	}

	// Verify token 1 with known kid -> MUST SUCCEED
	pubKeyFound, err := km.GetVerificationKey("key-primary")
	if err != nil || pubKeyFound != pubKey1 {
		t.Fatalf("expected pubKey1, got %v, err: %v", pubKeyFound, err)
	}

	// 2. Generate token signed with key-transitional
	token2 := jwt.NewWithClaims(jwt.SigningMethodRS256, claims1)
	token2.Header["kid"] = "key-transitional"
	signed2, err := token2.SignedString(privKey2)
	if err != nil {
		t.Fatalf("failed to sign token 2: %v", err)
	}

	// Verify token 2 with known transitional kid -> MUST SUCCEED
	pubKeyFound2, err := km.GetVerificationKey("key-transitional")
	if err != nil || pubKeyFound2 != pubKey2 {
		t.Fatalf("expected pubKey2, got %v, err: %v", pubKeyFound2, err)
	}

	// 3. CRITICAL SECURITY ASSERTION: Token with UNKNOWN kid -> MUST FAIL CLOSED
	_, errUnknown := km.GetVerificationKey("malicious-or-unknown-key-id")
	if errUnknown == nil {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Unknown kid did not fail closed!")
	}

	// 4. Token without kid header -> MUST FALL BACK TO LEGACY KEY
	legacyKey, err := km.GetVerificationKey("")
	if err != nil || legacyKey != pubKey1 {
		t.Fatalf("expected legacy key fallback to pubKey1, got %v, err: %v", legacyKey, err)
	}

	_ = signed1
	_ = signed2
}

func TestKeyManager_RolloverLifecycle(t *testing.T) {
	privPEM1, pubPEM1, _ := security.GenerateRSAKeypairPEM()
	privPEM2, pubPEM2, _ := security.GenerateRSAKeypairPEM()

	privKey1, _ := jwt.ParseRSAPrivateKeyFromPEM(privPEM1)
	pubKey1, _ := jwt.ParseRSAPublicKeyFromPEM(pubPEM1)

	privKey2, _ := jwt.ParseRSAPrivateKeyFromPEM(privPEM2)
	pubKey2, _ := jwt.ParseRSAPublicKeyFromPEM(pubPEM2)

	km := security.NewKeyManager()

	// Initial State: Key 1 is primary
	km.SetPrimaryKey("kid-2026-v1", privKey1, pubKey1)

	// Step 1: Promote Key 2 to primary, demote Key 1 to transitional
	km.SetPrimaryKey("kid-2026-v2", privKey2, pubKey2)
	km.AddTransitionalPublicKey("kid-2026-v1", pubKey1)

	// Signing key is now Key 2
	activeKID, activePrivKey, err := km.GetSigningKey()
	if err != nil || activeKID != "kid-2026-v2" || activePrivKey != privKey2 {
		t.Fatalf("expected active key kid-2026-v2, got %s", activeKID)
	}

	// Both Key 1 and Key 2 are in the JWKS trusted set
	allKeys := km.GetAllPublicKeys()
	if len(allKeys) != 2 {
		t.Fatalf("expected 2 public keys in JWKS set during rollover, got %d", len(allKeys))
	}
	if allKeys["kid-2026-v1"] != pubKey1 || allKeys["kid-2026-v2"] != pubKey2 {
		t.Fatalf("keys in JWKS map do not match expected keys")
	}

	// Step 2: Grace period ends -> Remove Key 1
	km.RemoveTransitionalPublicKey("kid-2026-v1")
	allKeysAfterGrace := km.GetAllPublicKeys()
	if len(allKeysAfterGrace) != 1 {
		t.Fatalf("expected 1 public key in JWKS set after grace period, got %d", len(allKeysAfterGrace))
	}

	// Key 1 is now rejected
	_, errRevoked := km.GetVerificationKey("kid-2026-v1")
	if errRevoked == nil {
		t.Fatalf("expected expired kid-2026-v1 to be rejected, but it succeeded")
	}
}
