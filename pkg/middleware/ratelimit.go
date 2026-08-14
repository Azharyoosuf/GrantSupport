package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"grantsupport/pkg/config"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/ports"
)

// ExtractClientIP extracts the client IP address from a request, stripping ephemeral TCP ports
// and verifying proxy headers against trusted proxy ranges to prevent IP spoofing.
func ExtractClientIP(r *http.Request, trustedProxies []string) string {
	socketHost := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		socketHost = host
	}
	socketHost = strings.TrimSpace(socketHost)

	// If no trusted proxies are configured, or if the direct socket connection is NOT from a trusted proxy,
	// return the direct socket TCP host to prevent header spoofing.
	if len(trustedProxies) == 0 || !ValidateIPWhitelist(socketHost, trustedProxies) {
		return socketHost
	}

	// Direct socket connection is from a trusted reverse proxy (e.g. Cloudflare / AWS ALB):
	// Inspect proxy headers in order of priority.
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		if net.ParseIP(cfIP) != nil {
			return cfIP
		}
	}

	if xRealIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); xRealIP != "" {
		if net.ParseIP(xRealIP) != nil {
			return xRealIP
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			firstIP := strings.TrimSpace(parts[0])
			if net.ParseIP(firstIP) != nil {
				return firstIP
			}
		}
	}

	return socketHost
}

// RateLimitMiddleware returns an HTTP middleware that throttles requests based on client IP.
// limit specifies the maximum allowed requests in windowSeconds.
func RateLimitMiddleware(limiter ports.RateLimiterStore, limit int, windowSeconds int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limiter == nil || limit <= 0 {
				next.ServeHTTP(w, r)
				return
			}

			var trustedProxies []string
			if config.AppConfig != nil {
				trustedProxies = config.AppConfig.TrustedProxies
			}

			clientIP := ExtractClientIP(r, trustedProxies)
			key := fmt.Sprintf("ip:%s:%s", clientIP, r.URL.Path)

			allowed, err := limiter.Allow(r.Context(), key, limit, time.Duration(windowSeconds)*time.Second)
			if err != nil {
				controller.WriteRFC7807Error(w, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "Rate limiting service temporarily unavailable; please retry later.")
				return
			}
			if !allowed {
				controller.WriteRFC7807Error(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Too many requests. Please retry later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
