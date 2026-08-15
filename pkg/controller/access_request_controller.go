package controller

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/service"
)

// AccessRequestController handles access request submission, listing, review, and approval.
type AccessRequestController struct {
	service *service.AccessRequestService
}

// NewAccessRequestController constructs an AccessRequestController.
func NewAccessRequestController(s *service.AccessRequestService) *AccessRequestController {
	return &AccessRequestController{service: s}
}

// CreateAccessRequest submits a new support access request.
// POST /api/v1/access-requests
func (c *AccessRequestController) CreateAccessRequest(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	input, err := DecodeAndValidate[CreateAccessRequestPayload](r)
	if err != nil {
		return err
	}
	req, err := c.service.CreateAccessRequest(r.Context(), tenant.InstitutionID, tenant.UserID, domain.CreateAccessRequestInput{
		TargetService: input.TargetService, Reason: input.Reason, DurationMinutes: input.DurationMinutes, Scope: input.Scope, WhitelistedIPs: input.WhitelistedIPs,
	})
	if err != nil {
		return NewAppError(http.StatusBadRequest, "CREATE_REQUEST_FAILED", err.Error())
	}
	WriteJSON(w, http.StatusCreated, req)
	return nil
}

// ListAccessRequests queries paginated access requests for the tenant.
// GET /api/v1/access-requests
func (c *AccessRequestController) ListAccessRequests(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	status := r.URL.Query().Get("status")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	var requesterID *uuid.UUID
	if tenant.Role == "SUPPORT_AGENT" {
		requesterID = &tenant.UserID
	}

	requests, err := c.service.ListAccessRequests(r.Context(), tenant.InstitutionID, status, requesterID, limit, offset)
	if err != nil {
		return NewAppError(http.StatusInternalServerError, "QUERY_FAILED", "Failed to retrieve access requests")
	}
	WriteJSON(w, http.StatusOK, map[string]any{"requests": requests, "count": len(requests)})
	return nil
}

// GetAccessRequest retrieves request details by ID.
// GET /api/v1/access-requests/{id}
func (c *AccessRequestController) GetAccessRequest(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return NewAppError(http.StatusBadRequest, "INVALID_ID", "Invalid access request ID format")
	}
	req, err := c.service.GetAccessRequest(r.Context(), tenant.InstitutionID, id)
	if err != nil {
		if errors.Is(err, repository.ErrAccessRequestNotFound) {
			return NewAppError(http.StatusNotFound, "REQUEST_NOT_FOUND", "Access request not found")
		}
		return NewAppError(http.StatusInternalServerError, "QUERY_FAILED", err.Error())
	}
	WriteJSON(w, http.StatusOK, req)
	return nil
}
