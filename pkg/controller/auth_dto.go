package controller

import (
	"net/http"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
)

// GrantSupportInput captures support delegation duration, scopes, and IP restrictions.
type GrantSupportInput struct {
	DurationMinutes int      `json:"durationMinutes" validate:"gte=1,lte=1440"`
	Scope           string   `json:"scope,omitempty" validate:"omitempty,max=64"`
	WhitelistedIPs  []string `json:"whitelistedIps,omitempty"`
}

// SupportLoginInput captures support token payload and explicit agent UUID.
type SupportLoginInput struct {
	Token   string `json:"token" validate:"required"`
	AgentID string `json:"agentId,omitempty" validate:"omitempty,uuid"`
}

// resolveCallerID extracts the effective caller UUID from explicit body, tenant context, or user context.
func resolveCallerID(r *http.Request, agentID string) (uuid.UUID, error) {
	if agentID != "" {
		parsed, err := uuid.Parse(agentID)
		if err != nil {
			return uuid.Nil, NewAppError(http.StatusBadRequest, "INVALID_AGENT_ID", "agentId must be a valid UUID")
		}
		return parsed, nil
	}
	if tenant, ok := pkgctx.GetTenant(r.Context()); ok && tenant != nil {
		return tenant.UserID, nil
	}
	if userID, ok := pkgctx.GetUser(r.Context()); ok {
		return userID, nil
	}
	return uuid.Nil, NewAppError(http.StatusBadRequest, "AGENT_ID_REQUIRED", "Explicit agentId UUID must be provided in request body")
}
