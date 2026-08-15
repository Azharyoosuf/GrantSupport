package controller

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"grantsupport/pkg/config"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/security"
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
		return NewAppError(http.StatusBadRequest, "GRANT_FAILED", "Failed to generate support access grant")
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

	var trustedProxies []string
	if config.AppConfig != nil {
		trustedProxies = config.AppConfig.TrustedProxies
	}
	clientIP := security.ExtractClientIP(r, trustedProxies)

	instID, jwtToken, err := c.grantService.SupportLogin(r.Context(), input.Token, callerID, clientIP)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", "Invalid or expired support grant token")
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
		return NewAppError(http.StatusInternalServerError, "REVOKE_FAILED", "Failed to revoke support delegations")
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
		return NewAppError(http.StatusInternalServerError, "LOGOUT_FAILED", "Failed to log out support agent session")
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Support agent session logged out successfully."})
	return nil
}

// GetActiveSessions lists all active delegated support sessions for the tenant.
// GET /api/v1/auth/support/sessions
func (c *SupportGrantController) GetActiveSessions(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	sessions, err := c.grantService.GetActiveSessions(r.Context(), tenant.InstitutionID)
	if err != nil {
		return NewAppError(http.StatusInternalServerError, "SESSIONS_FAILED", "Failed to retrieve active sessions")
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "sessions": sessions})
	return nil
}

// TerminateSession revokes a specific support session by grant ID.
// DELETE /api/v1/auth/support/sessions/{grantId}
func (c *SupportGrantController) TerminateSession(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	grantIDStr := chi.URLParam(r, "grantId")
	grantID, err := uuid.Parse(grantIDStr)
	if err != nil {
		return NewAppError(http.StatusBadRequest, "INVALID_GRANT_ID", "grantId must be a valid UUID")
	}
	if err := c.grantService.TerminateSession(r.Context(), tenant.InstitutionID, tenant.UserID, grantID); err != nil {
		return NewAppError(http.StatusInternalServerError, "TERMINATE_FAILED", "Failed to terminate support session")
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Support session terminated successfully."})
	return nil
}
