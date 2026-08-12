package controller

import (
	"net/http"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
)

// GrantSupport generates a temporary platform owner support audit token.
// POST /api/v1/auth/support/grant
func (c *AuthController) GrantSupport(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	input, err := DecodeAndValidate[GrantSupportInput](r)
	if err != nil {
		return err
	}

	token, err := c.authService.CreateSupportGrant(r.Context(), tenant.InstitutionID, tenant.UserID, input.DurationMinutes)
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

// SupportLogin authenticates a delegated platform auditor using a support token.
// POST /api/v1/auth/support/login
func (c *AuthController) SupportLogin(w http.ResponseWriter, r *http.Request) error {
	input, err := DecodeAndValidate[SupportLoginInput](r)
	if err != nil {
		return err
	}

	var callerID uuid.UUID
	if tenant, ok := pkgctx.GetTenant(r.Context()); ok && tenant != nil {
		callerID = tenant.UserID
	}

	user, instID, jwtToken, err := c.authService.SupportLogin(r.Context(), input.Token, callerID)
	if err != nil {
		return NewAppError(http.StatusUnauthorized, "SUPPORT_LOGIN_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"message":      "Delegated support login successful.",
		"access_token": jwtToken,
		"data": map[string]any{
			"user":           user,
			"institution_id": instID,
			"access_token":   jwtToken,
		},
	})
	return nil
}

// RevokeSupport revokes all active support delegations.
// POST /api/v1/auth/support/revoke
func (c *AuthController) RevokeSupport(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	if err := c.authService.RevokeSupportGrant(r.Context(), tenant.InstitutionID, tenant.UserID); err != nil {
		return NewAppError(http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "All support delegations revoked successfully.",
	})
	return nil
}

// LogoutAll revokes all active sessions for a user across all devices.
// POST /api/v1/auth/logout-all
func (c *AuthController) LogoutAll(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	if err := c.authService.RevokeAllSessions(r.Context(), tenant.UserID, tenant.InstitutionID); err != nil {
		return NewAppError(http.StatusInternalServerError, "REVOKE_FAILED", err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Logged out from all devices.",
	})
	return nil
}
