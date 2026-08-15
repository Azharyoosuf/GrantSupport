package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/ent/accessrequest"
	"grantsupport/pkg/domain"
)

var (
	// ErrAccessRequestNotFound indicates the request does not exist or belongs to another tenant.
	ErrAccessRequestNotFound = errors.New("ACCESS_REQUEST_NOT_FOUND: Access request not found")
	// ErrAccessRequestAlreadyResolved indicates the request has already transitioned to a terminal state.
	ErrAccessRequestAlreadyResolved = errors.New("ACCESS_REQUEST_ALREADY_RESOLVED: Access request has already been approved, rejected, or cancelled")
	// ErrAccessRequestExpired indicates the request TTL has expired.
	ErrAccessRequestExpired = errors.New("ACCESS_REQUEST_EXPIRED: Access request has expired and cannot be modified")
)

// AccessRequestRepository manages multi-tenant persistence and atomic CAS transitions for access requests.
type AccessRequestRepository struct {
	base *BaseRepository
}

// NewAccessRequestRepository constructs a new AccessRequestRepository.
func NewAccessRequestRepository(base *BaseRepository) *AccessRequestRepository {
	return &AccessRequestRepository{base: base}
}

// CreateAccessRequest persists a new pending access request.
func (r *AccessRequestRepository) CreateAccessRequest(ctx context.Context, req *domain.AccessRequest) (*ent.AccessRequest, error) {
	client, err := r.base.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	builder := client.AccessRequest.Create().
		SetID(req.ID).
		SetInstitutionID(req.InstitutionID).
		SetRequesterID(req.RequesterID).
		SetReason(req.Reason).
		SetRequestedDurationMinutes(req.RequestedDurationMinutes).
		SetRequestedScope(req.RequestedScope).
		SetRequestedIps(req.RequestedIPs).
		SetStatus(domain.AccessRequestStatusPending).
		SetExpiresAt(req.ExpiresAt).
		SetCreatedAt(req.CreatedAt)

	if req.TargetService != "" {
		builder.SetTargetService(req.TargetService)
	}

	return builder.Save(ctx)
}

// FindAccessRequestByID queries an access request by ID with strict tenant isolation.
func (r *AccessRequestRepository) FindAccessRequestByID(ctx context.Context, institutionID, requestID uuid.UUID) (*ent.AccessRequest, error) {
	client, err := r.base.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	record, err := client.AccessRequest.Query().
		Where(
			accessrequest.ID(requestID),
			accessrequest.InstitutionID(institutionID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrAccessRequestNotFound
		}
		return nil, fmt.Errorf("failed to query access request: %w", err)
	}

	return record, nil
}

// FindAccessRequestsByInstitution queries paginated access requests for an institution.
// If status is provided, it filters by status; if requesterID is provided, it restricts to that user.
func (r *AccessRequestRepository) FindAccessRequestsByInstitution(
	ctx context.Context,
	institutionID uuid.UUID,
	status string,
	requesterID *uuid.UUID,
	limit, offset int,
) ([]*ent.AccessRequest, error) {
	client, err := r.base.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	query := client.AccessRequest.Query().
		Where(accessrequest.InstitutionID(institutionID))

	if status != "" {
		query = query.Where(accessrequest.Status(status))
	}
	if requesterID != nil {
		query = query.Where(accessrequest.RequesterID(*requesterID))
	}

	return query.
		Order(ent.Desc(accessrequest.FieldCreatedAt)).
		Limit(limit).
		Offset(offset).
		All(ctx)
}

// ApproveRequestCAS performs an atomic conditional update transitioning a PENDING request to APPROVED inside a transaction.
func (r *AccessRequestRepository) ApproveRequestCAS(
	ctx context.Context,
	tx *ent.Tx,
	institutionID, requestID, approverID, grantID uuid.UUID,
	approvedDuration int,
	approvedScope string,
	approvedIPs []string,
) error {
	now := time.Now()

	count, err := tx.AccessRequest.Update().
		Where(
			accessrequest.ID(requestID),
			accessrequest.InstitutionID(institutionID),
			accessrequest.Status(domain.AccessRequestStatusPending),
			accessrequest.ExpiresAtGT(now),
		).
		SetStatus(domain.AccessRequestStatusApproved).
		SetApprovedByID(approverID).
		SetApprovedAt(now).
		SetSupportGrantID(grantID).
		SetApprovedDurationMinutes(approvedDuration).
		SetApprovedScope(approvedScope).
		SetApprovedIps(approvedIPs).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute approval CAS: %w", err)
	}

	if count == 0 {
		// Check if request exists or expired to return precise error
		existing, err := tx.AccessRequest.Query().
			Where(
				accessrequest.ID(requestID),
				accessrequest.InstitutionID(institutionID),
			).
			Only(ctx)
		if err != nil || existing == nil {
			return ErrAccessRequestNotFound
		}
		if now.After(existing.ExpiresAt) {
			return ErrAccessRequestExpired
		}
		return ErrAccessRequestAlreadyResolved
	}

	return nil
}

// RejectRequestCAS performs an atomic conditional update transitioning a PENDING request to REJECTED inside a transaction.
func (r *AccessRequestRepository) RejectRequestCAS(
	ctx context.Context,
	tx *ent.Tx,
	institutionID, requestID, rejecterID uuid.UUID,
	reason string,
) error {
	now := time.Now()

	count, err := tx.AccessRequest.Update().
		Where(
			accessrequest.ID(requestID),
			accessrequest.InstitutionID(institutionID),
			accessrequest.Status(domain.AccessRequestStatusPending),
			accessrequest.ExpiresAtGT(now),
		).
		SetStatus(domain.AccessRequestStatusRejected).
		SetRejectedByID(rejecterID).
		SetRejectedAt(now).
		SetRejectionReason(reason).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute rejection CAS: %w", err)
	}

	if count == 0 {
		existing, err := tx.AccessRequest.Query().
			Where(
				accessrequest.ID(requestID),
				accessrequest.InstitutionID(institutionID),
			).
			Only(ctx)
		if err != nil || existing == nil {
			return ErrAccessRequestNotFound
		}
		if now.After(existing.ExpiresAt) {
			return ErrAccessRequestExpired
		}
		return ErrAccessRequestAlreadyResolved
	}

	return nil
}

// CancelRequestCAS performs an atomic conditional update transitioning a PENDING request to CANCELLED.
func (r *AccessRequestRepository) CancelRequestCAS(
	ctx context.Context,
	tx *ent.Tx,
	institutionID, requestID uuid.UUID,
) error {
	now := time.Now()

	count, err := tx.AccessRequest.Update().
		Where(
			accessrequest.ID(requestID),
			accessrequest.InstitutionID(institutionID),
			accessrequest.Status(domain.AccessRequestStatusPending),
			accessrequest.ExpiresAtGT(now),
		).
		SetStatus(domain.AccessRequestStatusCancelled).
		SetCancelledAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute cancellation CAS: %w", err)
	}

	if count == 0 {
		existing, err := tx.AccessRequest.Query().
			Where(
				accessrequest.ID(requestID),
				accessrequest.InstitutionID(institutionID),
			).
			Only(ctx)
		if err != nil || existing == nil {
			return ErrAccessRequestNotFound
		}
		if now.After(existing.ExpiresAt) {
			return ErrAccessRequestExpired
		}
		return ErrAccessRequestAlreadyResolved
	}

	return nil
}
