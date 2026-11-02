package controller

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// GrantSupportInput captures support delegation duration, scopes, and IP restrictions.
type GrantSupportInput struct {
	DurationMinutes int `json:"durationMinutes" validate:"gte=1,lte=1440"`
	// Scope is passed through to the issued JWT's claims but is NOT enforced by GrantSupport itself —
	// the host application consuming the JWT is responsible for checking this claim before permitting
	// any action. This is intentional; do not assume GrantSupport restricts behavior based on scope.
	Scope          string   `json:"scope,omitempty" validate:"omitempty,max=64"`
	WhitelistedIPs []string `json:"whitelistedIps,omitempty"`
}

// SupportLoginInput captures support token payload and required explicit agent UUID.
type SupportLoginInput struct {
	Token   string `json:"token" validate:"required"`
	AgentID string `json:"agentId"`
}

// parseRequiredAgentID validates that an explicit, non-nil agentId UUID was supplied in the request body.
func parseRequiredAgentID(agentID string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(agentID)
	if trimmed == "" {
		return uuid.Nil, NewAppError(http.StatusBadRequest, "INVALID_INPUT", "agentId is required and must be a valid non-nil UUID")
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil || parsed == uuid.Nil {
		return uuid.Nil, NewAppError(http.StatusBadRequest, "INVALID_INPUT", "agentId is required and must be a valid non-nil UUID")
	}
	return parsed, nil
}
