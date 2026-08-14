package middleware_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"grantsupport/pkg/adapters/ratelimit"
	"grantsupport/pkg/config"
	"grantsupport/pkg/middleware"
)

func TestRateLimitMiddleware_EphemeralPortSharing(t *testing.T) {
	limiter := ratelimit.NewMemoryRateLimiter()
	handler := middleware.RateLimitMiddleware(limiter, 10, 60)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	// Send 10 requests from the same client IP (203.0.113.195) but each with a different ephemeral source port
	for port := 50000; port < 50010; port++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
		req.RemoteAddr = fmt.Sprintf("203.0.113.195:%d", port)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Request %d on port %d expected 200 OK, got: %d", port-50000+1, port, rec.Code)
		}
	}

	// 11th request from the same IP on yet another ephemeral port MUST be rejected with HTTP 429
	req11 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
	req11.RemoteAddr = "203.0.113.195:50011"
	rec11 := httptest.NewRecorder()

	handler.ServeHTTP(rec11, req11)
	if rec11.Code != http.StatusTooManyRequests {
		t.Fatalf("11th request expected 429 Too Many Requests, got: %d", rec11.Code)
	}

	// Request from a DIFFERENT IP on the same port should succeed
	reqOther := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
	reqOther.RemoteAddr = "198.51.100.4:50000"
	recOther := httptest.NewRecorder()

	handler.ServeHTTP(recOther, reqOther)
	if recOther.Code != http.StatusOK {
		t.Fatalf("Request from different IP expected 200 OK, got: %d", recOther.Code)
	}
}

func TestRateLimitMiddleware_SpoofedProxyHeaderIgnored(t *testing.T) {
	// Configure trusted proxies (only 127.0.0.1 is trusted)
	config.AppConfig = &config.Config{
		TrustedProxies: []string{"127.0.0.1"},
	}

	limiter := ratelimit.NewMemoryRateLimiter()
	handler := middleware.RateLimitMiddleware(limiter, 2, 60)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	// Direct socket connection is an UNTRUSTED public IP (198.51.100.50) attempting to spoof CF-Connecting-IP
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.50:%d", 40000+i)
		req.Header.Set("CF-Connecting-IP", fmt.Sprintf("10.0.0.%d", i)) // Attempts to rotate spoofed IP
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Request %d expected 200 OK, got: %d", i, rec.Code)
		}
	}

	// 3rd request with a different spoofed CF-Connecting-IP header must still be blocked
	// because socket IP 198.51.100.50 is exhausted!
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
	req3.RemoteAddr = "198.51.100.50:40003"
	req3.Header.Set("CF-Connecting-IP", "10.0.0.99")
	rec3 := httptest.NewRecorder()

	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("Spoofed header bypass attempt expected 429 Too Many Requests, got: %d", rec3.Code)
	}
}

func TestRateLimitMiddleware_TrustedProxyHeaderRespected(t *testing.T) {
	// Configure trusted proxies (10.0.0.1 is trusted proxy)
	config.AppConfig = &config.Config{
		TrustedProxies: []string{"10.0.0.1"},
	}

	limiter := ratelimit.NewMemoryRateLimiter()
	handler := middleware.RateLimitMiddleware(limiter, 2, 60)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	// Request coming from trusted proxy (10.0.0.1) on behalf of client 192.168.1.100
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
		req.RemoteAddr = "10.0.0.1:54321"
		req.Header.Set("CF-Connecting-IP", "192.168.1.100")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Trusted proxy request %d expected 200 OK, got: %d", i, rec.Code)
		}
	}

	// 3rd request from same client via trusted proxy is rate-limited
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
	req3.RemoteAddr = "10.0.0.1:54321"
	req3.Header.Set("CF-Connecting-IP", "192.168.1.100")
	rec3 := httptest.NewRecorder()

	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request expected 429 Too Many Requests, got: %d", rec3.Code)
	}

	// But a different client IP via the same trusted proxy is allowed
	reqDifferent := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
	reqDifferent.RemoteAddr = "10.0.0.1:54321"
	reqDifferent.Header.Set("CF-Connecting-IP", "192.168.1.200")
	recDifferent := httptest.NewRecorder()

	handler.ServeHTTP(recDifferent, reqDifferent)
	if recDifferent.Code != http.StatusOK {
		t.Fatalf("Different client via trusted proxy expected 200 OK, got: %d", recDifferent.Code)
	}
}

type errorRateLimiter struct{}

func (e *errorRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	return false, errors.New("redis connection failure")
}

func TestRateLimitMiddleware_LimiterErrorReturns503(t *testing.T) {
	limiter := &errorRateLimiter{}
	handler := middleware.RateLimitMiddleware(limiter, 10, 60)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503 Service Unavailable on rate limiter store failure, got: %d (%s)", rec.Code, rec.Body.String())
	}
}
