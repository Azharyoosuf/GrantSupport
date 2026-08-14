package middleware_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"grantsupport/pkg/config"
	"grantsupport/pkg/middleware"
)

// TestSecurityHeaders_StaticHeaders verifies standard baseline security headers are present on every response.
func TestSecurityHeaders_StaticHeaders(t *testing.T) {
	handler := middleware.SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if val := rec.Header().Get("X-Content-Type-Options"); val != "nosniff" {
		t.Errorf("Expected X-Content-Type-Options 'nosniff', got '%s'", val)
	}
	if val := rec.Header().Get("Referrer-Policy"); val != "strict-origin-when-cross-origin" {
		t.Errorf("Expected Referrer-Policy 'strict-origin-when-cross-origin', got '%s'", val)
	}
	if val := rec.Header().Get("X-Frame-Options"); val != "DENY" {
		t.Errorf("Expected X-Frame-Options 'DENY', got '%s'", val)
	}
}

// TestSecurityHeaders_HSTSBehavior verifies conditional HSTS header emission on HTTPS and trusted proxy requests.
func TestSecurityHeaders_HSTSBehavior(t *testing.T) {
	origConfig := config.AppConfig
	defer func() { config.AppConfig = origConfig }()

	config.AppConfig = &config.Config{
		HSTSEnabled:           true,
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           true,
		TrustedProxies:        []string{"10.0.0.1", "127.0.0.1"},
	}

	handler := middleware.SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Plaintext HTTP without TLS or Proxy -> No HSTS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/resource", nil)
		req.RemoteAddr = "192.168.1.50:12345"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if hsts := rec.Header().Get("Strict-Transport-Security"); hsts != "" {
			t.Fatalf("HSTS must not be emitted on unencrypted HTTP: got '%s'", hsts)
		}
	})

	t.Run("Direct TLS Connection -> Emits HSTS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/resource", nil)
		req.TLS = &tls.ConnectionState{} // Simulates TLS connection
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		expectedHSTS := "max-age=31536000; includeSubDomains; preload"
		if hsts := rec.Header().Get("Strict-Transport-Security"); hsts != expectedHSTS {
			t.Fatalf("Expected HSTS '%s', got '%s'", expectedHSTS, hsts)
		}
	})

	t.Run("Trusted Proxy Forwarded HTTPS -> Emits HSTS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/resource", nil)
		req.RemoteAddr = "10.0.0.1:45678" // Matches TrustedProxies
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if hsts := rec.Header().Get("Strict-Transport-Security"); hsts == "" {
			t.Fatal("Expected HSTS to be emitted for trusted proxy HTTPS request")
		}
	})

	t.Run("Untrusted Client Spoofed X-Forwarded-Proto -> No HSTS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/resource", nil)
		req.RemoteAddr = "203.0.113.195:54321" // Untrusted external IP
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if hsts := rec.Header().Get("Strict-Transport-Security"); hsts != "" {
			t.Fatalf("Security Violation: Spoofed X-Forwarded-Proto from untrusted IP was accepted; got HSTS: '%s'", hsts)
		}
	})
}

// TestHTTPToHTTPSRedirectHandler verifies redirection of plaintext HTTP requests to target HTTPS port.
func TestHTTPToHTTPSRedirectHandler(t *testing.T) {
	redirectHandler := middleware.HTTPToHTTPSRedirectHandler("8443")

	req := httptest.NewRequest("GET", "http://example.com/api/v1/auth/support/login?foo=bar", nil)
	rec := httptest.NewRecorder()

	redirectHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("Expected 308 Permanent Redirect, got %d", rec.Code)
	}

	expectedLocation := "https://example.com:8443/api/v1/auth/support/login?foo=bar"
	if loc := rec.Header().Get("Location"); loc != expectedLocation {
		t.Fatalf("Expected Location '%s', got '%s'", expectedLocation, loc)
	}
}
