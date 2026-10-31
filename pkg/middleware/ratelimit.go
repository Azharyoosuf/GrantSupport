package middleware

import (
	"fmt"
	"net/http"
	"time"

	"grantsupport/pkg/config"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/observability"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/security"
)

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

			clientIP := security.ExtractClientIP(r, trustedProxies)
			key := fmt.Sprintf("ip:%s:%s", clientIP, r.URL.Path)

			allowed, err := limiter.Allow(r.Context(), key, limit, time.Duration(windowSeconds)*time.Second)
			if err != nil {
				controller.WriteProblemDetailsError(w, r, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "Rate limiting service temporarily unavailable; please retry later.")
				return
			}
			if !allowed {
				observability.DefaultRegistry.IncRateLimitExceeded(NormalizeRoutePattern(r))
				controller.WriteProblemDetailsError(w, r, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Too many requests. Please retry later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
