package middleware

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/security"
)

// AuthMiddleware inspects Authorization headers (Bearer JWT) and injects Tenant Context into request context.
func AuthMiddleware(next http.Handler) http.Handler {
	return NewAuthMiddleware(nil)(next)
}

// NewAuthMiddleware constructs a JWT authentication middleware with optional token revocation check.
func NewAuthMiddleware(revocationStore ports.RevocationStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing or malformed Authorization header")
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := security.VerifyJWT(tokenStr)
			if err != nil || claims == nil {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "INVALID_TOKEN", "JWT signature verification or expiration check failed")
				return
			}

			instID, errInst := uuid.Parse(claims.InstitutionID)
			userID, errUser := uuid.Parse(claims.UserID)
			if errInst != nil || errUser != nil {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "INVALID_CLAIMS", "Malformed UUID claims in JWT payload")
				return
			}

			// TokenVersion revocation check (Fail-closed: missing revocation store or store error rejects request)
			if revocationStore == nil {
				controller.WriteRFC7807Error(w, http.StatusServiceUnavailable, "REVOCATION_CHECK_UNAVAILABLE", "Revocation store is not configured; unable to verify session revocation status.")
				return
			}

			revoked, err := revocationStore.IsTokenRevoked(r.Context(), claims.InstitutionID, claims.UserID, claims.TokenVersion)
			if err != nil {
				controller.WriteRFC7807Error(w, http.StatusServiceUnavailable, "REVOCATION_CHECK_UNAVAILABLE", "Unable to verify session revocation status; please retry.")
				return
			}
			if revoked {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Session has been revoked. Please log in again.")
				return
			}

			tenant := &pkgctx.TenantData{
				InstitutionID: instID,
				UserID:        userID,
				Role:          claims.Role,
			}

			ctx := pkgctx.WithTenant(r.Context(), tenant)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
