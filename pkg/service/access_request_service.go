package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/webhook"
)

var (
	// ErrSelfApprovalProhibited indicates that an agent cannot approve their own access request.
	ErrSelfApprovalProhibited = errors.New("SELF_APPROVAL_FORBIDDEN: Requesters cannot approve their own access requests")
	// ErrUnauthorizedCancellation indicates that a non-admin actor tried to cancel another user's request.
	ErrUnauthorizedCancellation = errors.New("UNAUTHORIZED_CANCELLATION: Only the requester or an institution administrator may cancel an access request")
	// ErrInvalidDuration indicates that the requested or approved duration is outside valid limits.
	ErrInvalidDuration = errors.New("INVALID_DURATION: Duration must be between 1 and 1440 minutes")
)

// AccessRequestService orchestrates access request submission, customer approval, atomic grant creation, and audit logging.
type AccessRequestService struct {
	baseRepo          *repository.BaseRepository
	accessRequestRepo *repository.AccessRequestRepository
	supportGrantRepo  *repository.SupportGrantRepository
	auditRepo         *repository.SecurityAuditRepository
	lockStore         ports.LockStore
	webhookDispatcher *webhook.WebhookDispatcher
}

// NewAccessRequestService constructs an AccessRequestService instance.
func NewAccessRequestService(
	baseRepo *repository.BaseRepository,
	accessRequestRepo *repository.AccessRequestRepository,
	supportGrantRepo *repository.SupportGrantRepository,
	auditRepo *repository.SecurityAuditRepository,
	lockStore ports.LockStore,
) *AccessRequestService {
	return &AccessRequestService{
		baseRepo:          baseRepo,
		accessRequestRepo: accessRequestRepo,
		supportGrantRepo:  supportGrantRepo,
		auditRepo:         auditRepo,
		lockStore:         lockStore,
	}
}

// SetWebhookDispatcher attaches an optional WebhookDispatcher for lifecycle event dispatches.
func (s *AccessRequestService) SetWebhookDispatcher(d *webhook.WebhookDispatcher) {
	s.webhookDispatcher = d
}

// CreateAccessRequest creates and persists a new pending access request.
func (s *AccessRequestService) CreateAccessRequest(
	ctx context.Context,
	institutionID, requesterID uuid.UUID,
	input domain.CreateAccessRequestInput,
) (*domain.AccessRequest, error) {
	if input.DurationMinutes < 1 || input.DurationMinutes > 1440 {
		return nil, ErrInvalidDuration
	}
	if input.Reason == "" {
		return nil, errors.New("INVALID_INPUT: Reason is required")
	}

	scope := input.Scope
	if scope == "" {
		scope = "FULL_ACCESS"
	}

	now := time.Now()
	reqDomain := &domain.AccessRequest{
		ID:                       uuid.Must(uuid.NewV7()),
		InstitutionID:            institutionID,
		RequesterID:              requesterID,
		TargetService:            input.TargetService,
		Reason:                   input.Reason,
		RequestedDurationMinutes: input.DurationMinutes,
		RequestedScope:           scope,
		RequestedIPs:             input.WhitelistedIPs,
		Status:                   domain.AccessRequestStatusPending,
		ExpiresAt:                now.Add(24 * time.Hour), // 24-hour pending request TTL
		CreatedAt:                now,
	}

	entRecord, err := s.accessRequestRepo.CreateAccessRequest(ctx, reqDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to persist access request: %w", err)
	}

	// Write audit log entry
	auditDesc := fmt.Sprintf("Access request submitted by %s for service '%s' (Duration: %dm, Scope: %s)",
		requesterID.String(), reqDomain.TargetService, reqDomain.RequestedDurationMinutes, reqDomain.RequestedScope)
	if s.auditRepo != nil {
		if _, logErr := s.auditRepo.LogSecurityEvent(ctx, institutionID, requesterID, "access_request.created", auditDesc, nil); logErr != nil {
			slog.Error("Failed to write audit event for access_request.created", slog.String("error", logErr.Error()))
		}
	}

	// Dispatch outbound webhook
	if s.webhookDispatcher != nil {
		event := webhook.NewWebhookEvent("access_request.created", institutionID.String(), requesterID.String(), map[string]any{
			"request_id":       reqDomain.ID.String(),
			"target_service":   reqDomain.TargetService,
			"duration_minutes": reqDomain.RequestedDurationMinutes,
			"scope":            reqDomain.RequestedScope,
		})
		s.webhookDispatcher.DispatchAsync(event)
	}

	return s.mapEntToDomain(entRecord), nil
}

// GetAccessRequest retrieves an access request by ID with strict tenant isolation.
func (s *AccessRequestService) GetAccessRequest(ctx context.Context, institutionID, requestID uuid.UUID) (*domain.AccessRequest, error) {
	entRecord, err := s.accessRequestRepo.FindAccessRequestByID(ctx, institutionID, requestID)
	if err != nil {
		return nil, err
	}
	return s.mapEntToDomain(entRecord), nil
}

// ListAccessRequests retrieves paginated access requests for an institution.
func (s *AccessRequestService) ListAccessRequests(
	ctx context.Context,
	institutionID uuid.UUID,
	status string,
	requesterID *uuid.UUID,
	limit, offset int,
) ([]*domain.AccessRequest, error) {
	records, err := s.accessRequestRepo.FindAccessRequestsByInstitution(ctx, institutionID, status, requesterID, limit, offset)
	if err != nil {
		return nil, err
	}

	res := make([]*domain.AccessRequest, len(records))
	for i, r := range records {
		res[i] = s.mapEntToDomain(r)
	}
	return res, nil
}

// ApproveAccessRequest atomically transitions the request to APPROVED, creates a SupportGrant, and logs the audit event.
// Security Invariants:
// 1. Self-approval is strictly prohibited (approverID != requesterID).
// 2. Approved duration cannot exceed requested duration.
// 3. Raw token is returned ONCE to the approving administrator in the response and is NEVER stored unhashed.
func (s *AccessRequestService) ApproveAccessRequest(
	ctx context.Context,
	institutionID, approverID, requestID uuid.UUID,
	input domain.ApproveAccessRequestInput,
) (*domain.ApproveAccessRequestResult, error) {
	// 1. Fetch current request to check ownership and state
	req, err := s.accessRequestRepo.FindAccessRequestByID(ctx, institutionID, requestID)
	if err != nil {
		return nil, err
	}

	// 2. SELF-APPROVAL CHECK: Must fail closed if the requester is the approver
	if req.RequesterID == approverID {
		return nil, ErrSelfApprovalProhibited
	}

	// 3. Determine approved parameters (Can narrow, cannot broaden)
	approvedDuration := req.RequestedDurationMinutes
	if input.DurationMinutes > 0 {
		if input.DurationMinutes > req.RequestedDurationMinutes {
			return nil, errors.New("INVALID_DURATION: Approved duration cannot exceed requested duration")
		}
		approvedDuration = input.DurationMinutes
	}

	approvedScope := req.RequestedScope
	if input.Scope != "" {
		approvedScope = input.Scope
	}

	approvedIPs := req.RequestedIps
	if len(input.WhitelistedIPs) > 0 {
		approvedIPs = input.WhitelistedIPs
	}

	// 4. Generate high-entropy single-use support grant token
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("cryptographic random generation failed: %w", err)
	}
	rawToken := fmt.Sprintf("%s_%s", institutionID.String(), hex.EncodeToString(randomBytes))
	tokenHashBytes := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	now := time.Now()
	grantExpiresAt := now.Add(time.Duration(approvedDuration) * time.Minute)
	grantID := uuid.Must(uuid.NewV7())

	// 5. ATOMIC DATABASE TRANSACTION BOUNDARY
	var createdGrant *ent.SupportGrant
	txErr := s.baseRepo.Transaction(ctx, func(tx *ent.Tx) error {
		// A. Atomic CAS Update on Access Request
		if err := s.accessRequestRepo.ApproveRequestCAS(ctx, tx, institutionID, requestID, approverID, grantID, approvedDuration, approvedScope, approvedIPs); err != nil {
			return err
		}

		// B. Insert SupportGrant
		var err error
		createdGrant, err = tx.SupportGrant.Create().
			SetID(grantID).
			SetInstitutionID(institutionID).
			SetGrantedByID(approverID).
			SetTokenHash(tokenHash).
			SetExpiresAt(grantExpiresAt).
			SetScope(approvedScope).
			SetWhitelistedIps(approvedIPs).
			SetCreatedAt(now).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to create support grant: %w", err)
		}

		// C. Write Audit Ledger Entry
		auditDesc := fmt.Sprintf("Access request %s approved by %s (Grant ID: %s, Duration: %dm, Scope: %s)",
			requestID.String(), approverID.String(), grantID.String(), approvedDuration, approvedScope)
		if s.auditRepo != nil {
			if _, logErr := s.auditRepo.LogSecurityEvent(ctx, institutionID, approverID, "access_request.approved", auditDesc, tx); logErr != nil {
				return fmt.Errorf("failed to write audit log in transaction: %w", logErr)
			}
		}

		return nil
	})

	if txErr != nil {
		return nil, txErr
	}

	// 6. POST-COMMIT SIDE EFFECTS (Non-blocking)
	if s.webhookDispatcher != nil {
		event := webhook.NewWebhookEvent("access_request.approved", institutionID.String(), approverID.String(), map[string]any{
			"request_id":       requestID.String(),
			"grant_id":         grantID.String(),
			"approved_by":      approverID.String(),
			"duration_minutes": approvedDuration,
			"scope":            approvedScope,
		})
		s.webhookDispatcher.DispatchAsync(event)
	}

	// Fetch updated request for clean response DTO
	updatedReq, _ := s.accessRequestRepo.FindAccessRequestByID(ctx, institutionID, requestID)

	domainGrant := &domain.SupportGrant{
		ID:             createdGrant.ID,
		InstitutionID:  createdGrant.InstitutionID,
		GrantedByID:    createdGrant.GrantedByID,
		ExpiresAt:      createdGrant.ExpiresAt,
		IsUsed:         createdGrant.IsUsed,
		Scope:          createdGrant.Scope,
		WhitelistedIPs: createdGrant.WhitelistedIps,
		CreatedAt:      createdGrant.CreatedAt,
	}

	return &domain.ApproveAccessRequestResult{
		Request:   s.mapEntToDomain(updatedReq),
		Grant:     domainGrant,
		RawToken:  rawToken,
		ExpiresAt: grantExpiresAt,
	}, nil
}

// RejectAccessRequest atomically transitions the request to REJECTED and logs the audit event.
func (s *AccessRequestService) RejectAccessRequest(
	ctx context.Context,
	institutionID, rejecterID, requestID uuid.UUID,
	input domain.RejectAccessRequestInput,
) error {
	if input.RejectionReason == "" {
		return errors.New("INVALID_INPUT: Rejection reason is required")
	}

	txErr := s.baseRepo.Transaction(ctx, func(tx *ent.Tx) error {
		if err := s.accessRequestRepo.RejectRequestCAS(ctx, tx, institutionID, requestID, rejecterID, input.RejectionReason); err != nil {
			return err
		}

		auditDesc := fmt.Sprintf("Access request %s rejected by %s (Reason: %s)",
			requestID.String(), rejecterID.String(), input.RejectionReason)
		if s.auditRepo != nil {
			if _, logErr := s.auditRepo.LogSecurityEvent(ctx, institutionID, rejecterID, "access_request.rejected", auditDesc, tx); logErr != nil {
				return fmt.Errorf("failed to write audit log in transaction: %w", logErr)
			}
		}

		return nil
	})

	if txErr != nil {
		return txErr
	}

	if s.webhookDispatcher != nil {
		event := webhook.NewWebhookEvent("access_request.rejected", institutionID.String(), rejecterID.String(), map[string]any{
			"request_id":       requestID.String(),
			"rejected_by":      rejecterID.String(),
			"rejection_reason": input.RejectionReason,
		})
		s.webhookDispatcher.DispatchAsync(event)
	}

	return nil
}

// CancelAccessRequest transitions a pending request to CANCELLED.
// Only the original requester or an institution administrator may cancel a request.
func (s *AccessRequestService) CancelAccessRequest(
	ctx context.Context,
	institutionID, actorID, requestID uuid.UUID,
	isCallerAdmin bool,
) error {
	req, err := s.accessRequestRepo.FindAccessRequestByID(ctx, institutionID, requestID)
	if err != nil {
		return err
	}

	if !isCallerAdmin && req.RequesterID != actorID {
		return ErrUnauthorizedCancellation
	}

	txErr := s.baseRepo.Transaction(ctx, func(tx *ent.Tx) error {
		if err := s.accessRequestRepo.CancelRequestCAS(ctx, tx, institutionID, requestID); err != nil {
			return err
		}

		auditDesc := fmt.Sprintf("Access request %s cancelled by %s", requestID.String(), actorID.String())
		if s.auditRepo != nil {
			if _, logErr := s.auditRepo.LogSecurityEvent(ctx, institutionID, actorID, "access_request.cancelled", auditDesc, tx); logErr != nil {
				return fmt.Errorf("failed to write audit log in transaction: %w", logErr)
			}
		}

		return nil
	})

	if txErr != nil {
		return txErr
	}

	if s.webhookDispatcher != nil {
		event := webhook.NewWebhookEvent("access_request.cancelled", institutionID.String(), actorID.String(), map[string]any{
			"request_id":   requestID.String(),
			"cancelled_by": actorID.String(),
		})
		s.webhookDispatcher.DispatchAsync(event)
	}

	return nil
}

func (s *AccessRequestService) mapEntToDomain(e *ent.AccessRequest) *domain.AccessRequest {
	if e == nil {
		return nil
	}

	res := &domain.AccessRequest{
		ID:                       e.ID,
		InstitutionID:            e.InstitutionID,
		RequesterID:              e.RequesterID,
		Reason:                   e.Reason,
		RequestedDurationMinutes: e.RequestedDurationMinutes,
		RequestedScope:           e.RequestedScope,
		RequestedIPs:             e.RequestedIps,
		Status:                   e.Status,
		ExpiresAt:                e.ExpiresAt,
		CreatedAt:                e.CreatedAt,
	}

	if e.TargetService != nil {
		res.TargetService = *e.TargetService
	}

	if e.ApprovedDurationMinutes != nil {
		val := *e.ApprovedDurationMinutes
		res.ApprovedDurationMinutes = &val
	}
	if e.ApprovedScope != nil {
		val := *e.ApprovedScope
		res.ApprovedScope = &val
	}
	if len(e.ApprovedIps) > 0 {
		res.ApprovedIPs = e.ApprovedIps
	}
	if e.ApprovedByID != nil {
		val := *e.ApprovedByID
		res.ApprovedByID = &val
	}
	if e.ApprovedAt != nil {
		val := *e.ApprovedAt
		res.ApprovedAt = &val
	}
	if e.RejectedByID != nil {
		val := *e.RejectedByID
		res.RejectedByID = &val
	}
	if e.RejectionReason != nil {
		val := *e.RejectionReason
		res.RejectionReason = &val
	}
	if e.RejectedAt != nil {
		val := *e.RejectedAt
		res.RejectedAt = &val
	}
	if e.CancelledAt != nil {
		val := *e.CancelledAt
		res.CancelledAt = &val
	}
	if e.SupportGrantID != nil {
		val := *e.SupportGrantID
		res.SupportGrantID = &val
	}

	// Apply dynamic expiration mapping
	res.Status = res.EffectiveStatus()

	return res
}
