package controller

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/service"
)

// ApproveAccessRequest handles customer approval and one-time token issuance.
// POST /api/v1/access-requests/{id}/approve
func (c *AccessRequestController) ApproveAccessRequest(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return NewAppError(http.StatusBadRequest, "INVALID_ID", "Invalid access request ID format")
	}
	input, _ := DecodeAndValidate[ApproveAccessRequestPayload](r)
	result, err := c.service.ApproveAccessRequest(r.Context(), tenant.InstitutionID, tenant.UserID, id, domain.ApproveAccessRequestInput{
		DurationMinutes: input.DurationMinutes, Scope: input.Scope, WhitelistedIPs: input.WhitelistedIPs,
	})
	if err != nil {
		if errors.Is(err, service.ErrSelfApprovalProhibited) {
			return NewAppError(http.StatusForbidden, "SELF_APPROVAL_FORBIDDEN", err.Error())
		}
		if errors.Is(err, repository.ErrAccessRequestNotFound) {
			return NewAppError(http.StatusNotFound, "REQUEST_NOT_FOUND", "Access request not found")
		}
		if errors.Is(err, repository.ErrAccessRequestExpired) {
			return NewAppError(http.StatusGone, "REQUEST_EXPIRED", "Access request has expired and cannot be approved")
		}
		if errors.Is(err, repository.ErrAccessRequestAlreadyResolved) {
			return NewAppError(http.StatusConflict, "REQUEST_ALREADY_RESOLVED", "Access request is already resolved")
		}
		return NewAppError(http.StatusBadRequest, "APPROVE_FAILED", err.Error())
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "requestId": result.Request.ID, "status": result.Request.Status, "grantId": result.Grant.ID, "rawToken": result.RawToken, "expiresAt": result.ExpiresAt})
	return nil
}

// RejectAccessRequest handles customer denial of an access request.
// POST /api/v1/access-requests/{id}/reject
func (c *AccessRequestController) RejectAccessRequest(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return NewAppError(http.StatusBadRequest, "INVALID_ID", "Invalid access request ID format")
	}
	input, err := DecodeAndValidate[RejectAccessRequestPayload](r)
	if err != nil {
		return err
	}
	if err := c.service.RejectAccessRequest(r.Context(), tenant.InstitutionID, tenant.UserID, id, domain.RejectAccessRequestInput{RejectionReason: input.RejectionReason}); err != nil {
		if errors.Is(err, repository.ErrAccessRequestNotFound) {
			return NewAppError(http.StatusNotFound, "REQUEST_NOT_FOUND", "Access request not found")
		}
		if errors.Is(err, repository.ErrAccessRequestAlreadyResolved) {
			return NewAppError(http.StatusConflict, "REQUEST_ALREADY_RESOLVED", "Access request is already resolved")
		}
		return NewAppError(http.StatusBadRequest, "REJECT_FAILED", err.Error())
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Access request rejected successfully."})
	return nil
}

// CancelAccessRequest handles cancellation of an access request.
// POST /api/v1/access-requests/{id}/cancel
func (c *AccessRequestController) CancelAccessRequest(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return NewAppError(http.StatusBadRequest, "INVALID_ID", "Invalid access request ID format")
	}
	isAdmin := tenant.Role == "ADMIN" || tenant.Role == "ADMINISTRATOR" || tenant.Role == "OWNER" || tenant.Role == "OPERATOR"
	if err := c.service.CancelAccessRequest(r.Context(), tenant.InstitutionID, tenant.UserID, id, isAdmin); err != nil {
		if errors.Is(err, service.ErrUnauthorizedCancellation) {
			return NewAppError(http.StatusForbidden, "UNAUTHORIZED_CANCELLATION", err.Error())
		}
		if errors.Is(err, repository.ErrAccessRequestNotFound) {
			return NewAppError(http.StatusNotFound, "REQUEST_NOT_FOUND", "Access request not found")
		}
		if errors.Is(err, repository.ErrAccessRequestAlreadyResolved) {
			return NewAppError(http.StatusConflict, "REQUEST_ALREADY_RESOLVED", "Access request is already resolved")
		}
		return NewAppError(http.StatusBadRequest, "CANCEL_FAILED", err.Error())
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Access request cancelled successfully."})
	return nil
}
