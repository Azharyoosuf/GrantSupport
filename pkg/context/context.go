package pkgctx

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const (
	tenantIDKey contextKey = "tenant_id"
	userIDKey   contextKey = "user_id"
	roleKey     contextKey = "user_role"
)

// WithTenant stores institution ID in context.
func WithTenant(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// GetTenant retrieves institution ID from context.
func GetTenant(ctx context.Context) (uuid.UUID, bool) {
	val, ok := ctx.Value(tenantIDKey).(uuid.UUID)
	return val, ok
}

// WithUser stores user ID in context.
func WithUser(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// GetUser retrieves user ID from context.
func GetUser(ctx context.Context) (uuid.UUID, bool) {
	val, ok := ctx.Value(userIDKey).(uuid.UUID)
	return val, ok
}

// WithRole stores user role in context.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleKey, role)
}

// GetRole retrieves user role from context.
func GetRole(ctx context.Context) (string, bool) {
	val, ok := ctx.Value(roleKey).(string)
	return val, ok
}
