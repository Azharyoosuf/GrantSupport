package controller

import (
	"net/http"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/service"
)

// SupportGrantController handles delegated support grant HTTP endpoints.
type SupportGrantController struct {
	grantService *service.GrantSupportService
}

// NewSupportGrantController constructs a SupportGrantController instance.
func NewSupportGrantController(grantService *service.GrantSupportService) *SupportGrantController {
	return &SupportGrantController{
		grantService: grantService,
	}
}

// GrantSupport generates a temporary platform owner support audit token.
// POST /api/v1/auth/support/grant
func (c *SupportGrantController) GrantSupport(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	input, err := DecodeAndValidate[GrantSupportInput](r)
	if err != nil {
		return err
	}

	token, err := c.grantService.CreateSupportGrantScoped(r.Context(), tenant.InstitutionID, tenant.UserID, input.DurationMinutes, input.Scope, input.WhitelistedIPs)
	if err != nil {
		return NewAppError(http.StatusBadRequest, "GRANT_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"message": "Support access token generated successfully.",
		"token":   token,
	})
	return nil
}

// SupportLogin authenticates a delegated support agent using a support token.
// POST /api/v1/auth/support/login
func (c *SupportGrantController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}

	var callerID uuid.UUID
	if input.AgentID != "" {
		parsed, err := uuid.Parse(input.AgentID)
		if err != nil {
			return NewAppError(http.StatusBadRequest, "INVALID_AGENT_ID", "agentId must be a valid UUID")
		}
		callerID = parsed
	} else if tenant, ok := pkgctx.GetTenant(r.Context()); ok && tenant != nil {
		callerID = tenant.UserID
	} else if userID, ok := pkgctx.GetUser(r.Context()); ok {
		callerID = userID
	} else {
		return NewAppError(http.StatusBadRequest, "AGENT_ID_REQUIRED", "Explicit agentId UUID must be provided in request body")
	}

	instID, jwtToken, err := c.grantService.SupportLogin(r.Context(), input.Token, callerID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Delegated support login successful.",
		"access_token": jwtToken,
		"data": map[string]any{
			"institution_id": instID,
			"access_token":   jwtToken,
		},
	})
	return nil
}

// RevokeSupport revokes all active support delegations for an institution.
// POST /api/v1/auth/support/revoke
func (c *SupportGrantController) RevokeSupport(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	if err := c.grantService.RevokeSupportGrant(r.Context(), tenant.InstitutionID, tenant.UserID); err != nil {
		return NewAppError(http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "All support delegations revoked successfully.",
	})
	return nil
}
