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
