package pkgctx

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const (
	tenantKey contextKey = "tenant_data"
	userKey   contextKey = "user_id"
	roleKey   contextKey = "user_role"
)

// TenantData holds the authenticated tenant context for a request.
type TenantData struct {
	InstitutionID uuid.UUID
	UserID        uuid.UUID
	Role          string
}

// WithTenant stores TenantData in context.
func WithTenant(ctx context.Context, tenant *TenantData) context.Context {
	return context.WithValue(ctx, tenantKey, tenant)
}

// GetTenant retrieves TenantData from context.
func GetTenant(ctx context.Context) (*TenantData, bool) {
	val, ok := ctx.Value(tenantKey).(*TenantData)
	return val, ok
}

// WithUser stores user ID in context.
func WithUser(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userKey, userID)
}

// GetUser retrieves user ID from context.
func GetUser(ctx context.Context) (uuid.UUID, bool) {
	if val, ok := ctx.Value(userKey).(uuid.UUID); ok {
		return val, true
	}
	if tenant, ok := GetTenant(ctx); ok && tenant != nil {
		return tenant.UserID, true
	}
	return uuid.Nil, false
}

// WithRole stores user role in context.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleKey, role)
}

// GetRole retrieves user role from context.
func GetRole(ctx context.Context) (string, bool) {
	if val, ok := ctx.Value(roleKey).(string); ok {
		return val, true
	}
	if tenant, ok := GetTenant(ctx); ok && tenant != nil {
		return tenant.Role, true
	}
	return "", false
}
