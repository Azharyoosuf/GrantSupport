package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"grantsupport/pkg/cache"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/security"
)

// AuthMiddleware inspects Authorization headers (Bearer JWT) or 5-Layer Dual-Key headers (X-API-KEY-ID) and injects Tenant Context into request context.
func AuthMiddleware(next http.Handler) http.Handler {
	return NewAuthMiddleware(nil)(next)
}

// NewAuthMiddleware constructs a JWT authentication middleware with optional Valkey token version revocation check.
func NewAuthMiddleware(valkey *cache.ValkeyClient) func(http.Handler) http.Handler {
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

			// TokenVersion revocation check against Valkey security cache
			if valkey != nil && valkey.Client != nil {
				cacheKey := fmt.Sprintf("cache:%s:user:security:%s", claims.InstitutionID, claims.UserID)
				cachedVersion, err := valkey.Client.Get(r.Context(), cacheKey).Int()
				if err == nil && cachedVersion > claims.TokenVersion {
					controller.WriteRFC7807Error(w, http.StatusUnauthorized, "TOKEN_REVOKED", "Session has been revoked. Please log in again.")
					return
				}
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
