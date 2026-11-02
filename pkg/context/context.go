package pkgctx

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const (
	tenantKey contextKey = "tenant_data"
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
