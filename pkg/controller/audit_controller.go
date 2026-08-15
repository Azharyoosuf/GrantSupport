package controller

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/service"
)

// AuditController handles HTTP endpoints for querying and verifying the cryptographic audit ledger.
type AuditController struct {
	auditService *service.SecurityAuditService
}

// NewAuditController constructs an AuditController instance.
func NewAuditController(auditService *service.SecurityAuditService) *AuditController {
	return &AuditController{auditService: auditService}
}

// GetAuditEvents retrieves paginated audit events for the authenticated tenant.
// GET /api/v1/audit/events
func (c *AuditController) GetAuditEvents(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	var actorID *uuid.UUID
	if actorStr := r.URL.Query().Get("actor_id"); actorStr != "" {
		if parsedActor, err := uuid.Parse(actorStr); err == nil {
			actorID = &parsedActor
		} else {
			return NewAppError(http.StatusBadRequest, "INVALID_ACTOR_ID", "actor_id must be a valid UUID")
		}
	}

	var eventType *string
	if evType := r.URL.Query().Get("event_type"); evType != "" {
		eventType = &evType
	}

	events, err := c.auditService.GetAuditEvents(r.Context(), tenant.InstitutionID, actorID, eventType, limit, offset)
	if err != nil {
		return NewAppError(http.StatusInternalServerError, "AUDIT_QUERY_FAILED", "Failed to retrieve audit events")
	}

	type AuditEventResponseItem struct {
		ID            uuid.UUID `json:"id"`
		InstitutionID uuid.UUID `json:"institution_id"`
		ActorID       uuid.UUID `json:"actor_id"`
		EventType     string    `json:"event_type"`
		Description   string    `json:"description"`
		HashChain     string    `json:"hash_chain"`
		CreatedAt     string    `json:"created_at"`
	}

	items := make([]AuditEventResponseItem, 0, len(events))
	for _, e := range events {
		items = append(items, AuditEventResponseItem{
			ID:            e.ID,
			InstitutionID: e.InstitutionID,
			ActorID:       e.ActorID,
			EventType:     e.EventType,
			Description:   e.Description,
			HashChain:     e.HashChain,
			CreatedAt:     e.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
		})
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"events":  items,
		"limit":   limit,
		"offset":  offset,
	})
	return nil
}

// VerifyAuditChain cryptographically verifies the SHA-256 hash chain for the authenticated tenant.
// POST /api/v1/audit/verify
func (c *AuditController) VerifyAuditChain(w http.ResponseWriter, r *http.Request) error {
	tenant, ok := pkgctx.GetTenant(r.Context())
	if !ok || tenant == nil {
		return NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "User auth context not found")
	}

	valid, err := c.auditService.VerifyAuditChain(r.Context(), tenant.InstitutionID)
	if err != nil {
		return NewAppError(http.StatusInternalServerError, "AUDIT_VERIFICATION_FAILED", "Failed to verify audit ledger: "+err.Error())
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":        true,
		"valid":          valid,
		"institution_id": tenant.InstitutionID,
		"message":        "Audit log cryptographic hash chain is valid and unbroken.",
	})
	return nil
}
