package controller

import (
	"net/http"

	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/service"
)

// SupportGrantController handles delegated support grant HTTP endpoints.
type SupportGrantController struct {
	grantService *service.GrantSupportService
}

// NewSupportGrantController constructs a SupportGrantController instance.
func NewSupportGrantController(grantService *service.GrantSupportService) *SupportGrantController {
	return &SupportGrantController{grantService: grantService}
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
	WriteJSON(w, http.StatusCreated, map[string]any{"success": true, "message": "Support access token generated successfully.", "token": token})
	return nil
}

// SupportLogin authenticates a delegated support agent using a support token.
// POST /api/v1/auth/support/login
func (c *SupportGrantController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}
	callerID, err := resolveCallerID(r, input.AgentID)
	if err != nil {
		return err
	}
	instID, jwtToken, err := c.grantService.SupportLogin(r.Context(), input.Token, callerID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Support agent authenticated successfully.", "institution_id": instID, "access_token": jwtToken, "accessToken": jwtToken, "data": map[string]any{"institution_id": instID, "access_token": jwtToken}})
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
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "All support delegations revoked successfully."})
	return nil
}

// SupportLogout invalidates the authenticated support agent's active session.
// POST /api/v1/auth/support/logout
func (c *SupportGrantController) SupportLogout(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	if err := c.grantService.SupportLogout(r.Context(), tenant.InstitutionID, tenant.UserID); err != nil {
		return NewAppError(http.StatusInternalServerError, "LOGOUT_FAILED", err.Error())
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Support agent session logged out successfully."})
	return nil
}
