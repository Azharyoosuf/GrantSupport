package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"grantsupport/pkg/observability"
)

var knownStaticRoutes = map[string]bool{
	"/health":                       true,
	"/health/live":                  true,
	"/health/ready":                 true,
	"/metrics":                      true,
	"/.well-known/jwks.json":        true,
	"/api/v1/auth/support/login":    true,
	"/api/v1/auth/support/grant":    true,
	"/api/v1/auth/support/revoke":   true,
	"/api/v1/auth/support/logout":   true,
	"/api/v1/auth/support/sessions": true,
	"/api/v1/audit/events":          true,
	"/api/v1/audit/verify":          true,
}

// NormalizeRoutePattern returns a low-cardinality route pattern for metric labels,
// never exposing raw path parameters (UUIDs), tenant IDs, user IDs, or arbitrary 404 paths.
func NormalizeRoutePattern(r *http.Request) string {
	if r == nil {
		return "unmatched"
	}
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if pattern := rctx.RoutePattern(); pattern != "" {
			return pattern
		}
	}
	path := r.URL.Path
	if knownStaticRoutes[path] {
		return path
	}
	if strings.HasPrefix(path, "/api/v1/auth/support/sessions/") {
		return "/api/v1/auth/support/sessions/{grantId}"
	}
	return "unmatched"
}

// MetricsMiddleware records HTTP request counts and durations per normalized route pattern.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		route := NormalizeRoutePattern(r)
		observability.DefaultRegistry.RecordHTTPRequest(route, status, time.Since(start))
	})
}
