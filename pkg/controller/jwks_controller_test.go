package controller_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/security"
)

func TestJWKS_ValidStructureAndNoPrivateKeyLeakage(t *testing.T) {
	if err := security.SetupTestRSAKeys(); err != nil {
		t.Fatalf("failed to setup RSA keys: %v", err)
	}

	jwksCtrl := controller.NewJWKSController()
	handler := controller.CatchAsync(jwksCtrl.GetJWKS)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var rawMap map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rawMap); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	keysRaw, ok := rawMap["keys"].([]any)
	if !ok || len(keysRaw) != 1 {
		t.Fatalf("expected keys array of length 1, got %v", rawMap["keys"])
	}

	keyObj, ok := keysRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("expected key object, got %T", keysRaw[0])
	}

	// Verify standard JWK fields
	if keyObj["kty"] != "RSA" {
		t.Errorf("expected kty 'RSA', got %v", keyObj["kty"])
	}
	if keyObj["use"] != "sig" {
		t.Errorf("expected use 'sig', got %v", keyObj["use"])
	}
	if keyObj["alg"] != "RS256" {
		t.Errorf("expected alg 'RS256', got %v", keyObj["alg"])
	}
	if keyObj["n"] == nil || keyObj["n"] == "" {
		t.Errorf("expected non-empty modulus 'n'")
	}
	if keyObj["e"] == nil || keyObj["e"] == "" {
		t.Errorf("expected non-empty exponent 'e'")
	}

	// CRITICAL SECURITY ASSERTION: Verify ZERO private key parameters are present
	privateFields := []string{"d", "p", "q", "dp", "dq", "qi", "oth", "private_key"}
	for _, field := range privateFields {
		if _, exists := keyObj[field]; exists {
			t.Fatalf("CRITICAL SECURITY VIOLATION: Private key parameter '%s' found in public JWKS response!", field)
		}
	}
}

func TestJWKS_VerifyJWTWithExtractedPublicKey(t *testing.T) {
	if err := security.SetupTestRSAKeys(); err != nil {
		t.Fatalf("failed to setup RSA keys: %v", err)
	}

	// Generate a valid RS256 token
	tokenStr, err := security.GenerateJWT("test-user", "test-inst", "SUPPORT_AGENT", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	// Fetch JWKS
	jwksCtrl := controller.NewJWKSController()
	handler := controller.CatchAsync(jwksCtrl.GetJWKS)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var jwksResp controller.JWKSResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &jwksResp); err != nil {
		t.Fatalf("failed to decode JWKS: %v", err)
	}

	if len(jwksResp.Keys) == 0 {
		t.Fatalf("empty JWKS keys list")
	}

	key := jwksResp.Keys[0]

	// Reconstruct rsa.PublicKey from JWK n and e base64url strings
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		t.Fatalf("failed to decode modulus: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		t.Fatalf("failed to decode exponent: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	reconstructedPubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	// Verify the token using the reconstructed public key
	parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return reconstructedPubKey, nil
	})
	if err != nil {
		t.Fatalf("JWT verification failed using reconstructed JWKS key: %v", err)
	}
	if !parsedToken.Valid {
		t.Fatalf("token parsed with JWKS key was not valid")
	}
}
