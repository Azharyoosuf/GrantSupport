package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type correlationIDKey struct{}

// CorrelationIDMiddleware attaches or propagates an X-Correlation-ID header for distributed trace logging.
func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := r.Header.Get("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		w.Header().Set("X-Correlation-ID", correlationID)
		ctx := context.WithValue(r.Context(), correlationIDKey{}, correlationID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
