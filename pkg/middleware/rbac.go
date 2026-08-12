package middleware

import (
	"net/http"

	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
)

// RequireRoles returns a middleware function enforcing role-based access control (RBAC).
func RequireRoles(allowedRoles ...string) func(http.Handler) http.Handler {
	allowedMap := make(map[string]bool)
	for _, role := range allowedRoles {
		allowedMap[role] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := pkgctx.GetTenant(r.Context())
			if !ok || tenant == nil {
				controller.WriteRFC7807Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
				return
			}

			if !allowedMap[tenant.Role] {
				controller.WriteRFC7807Error(w, http.StatusForbidden, "FORBIDDEN", "You do not have permission to perform this action")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
