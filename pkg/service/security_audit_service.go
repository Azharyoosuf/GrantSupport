package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/pkg/repository"
)

// SecurityAuditService provides high-level domain operations for query and verification of the cryptographic audit ledger.
type SecurityAuditService struct {
	auditRepo *repository.SecurityAuditRepository
}

// NewSecurityAuditService constructs a SecurityAuditService instance.
func NewSecurityAuditService(auditRepo *repository.SecurityAuditRepository) *SecurityAuditService {
	return &SecurityAuditService{auditRepo: auditRepo}
}

// GetAuditEvents retrieves paginated audit events strictly scoped to institutionID with optional actor and event_type filtering.
func (s *SecurityAuditService) GetAuditEvents(ctx context.Context, institutionID uuid.UUID, actorID *uuid.UUID, eventType *string, limit, offset int) ([]*ent.AuditEvent, error) {
	if s.auditRepo == nil {
		return nil, errors.New("AUDIT_UNAVAILABLE: SecurityAuditRepository not configured")
	}
	return s.auditRepo.GetAuditEventsFiltered(ctx, institutionID, actorID, eventType, limit, offset)
}

// VerifyAuditChain cryptographically verifies the SHA-256 hash chain for an institution.
func (s *SecurityAuditService) VerifyAuditChain(ctx context.Context, institutionID uuid.UUID) (bool, error) {
	if s.auditRepo == nil {
		return false, errors.New("AUDIT_UNAVAILABLE: SecurityAuditRepository not configured")
	}
	return s.auditRepo.VerifyAuditChain(ctx, institutionID)
}
