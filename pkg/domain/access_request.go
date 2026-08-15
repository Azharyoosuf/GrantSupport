package domain

import (
	"time"

	"github.com/google/uuid"
)

// AccessRequest status constants.
const (
	AccessRequestStatusPending   = "PENDING"
	AccessRequestStatusApproved  = "APPROVED"
	AccessRequestStatusRejected  = "REJECTED"
	AccessRequestStatusCancelled = "CANCELLED"
	AccessRequestStatusExpired   = "EXPIRED"
)

// AccessRequest represents an in-band Just-In-Time (JIT) delegated support access request.
type AccessRequest struct {
	ID                       uuid.UUID  `json:"id"`
	InstitutionID            uuid.UUID  `json:"institutionId"`
	RequesterID              uuid.UUID  `json:"requesterId"`
	TargetService            string     `json:"targetService,omitempty"`
	Reason                   string     `json:"reason"`
	RequestedDurationMinutes int        `json:"requestedDurationMinutes"`
	ApprovedDurationMinutes  *int       `json:"approvedDurationMinutes,omitempty"`
	RequestedScope           string     `json:"requestedScope"`
	ApprovedScope            *string    `json:"approvedScope,omitempty"`
	RequestedIPs             []string   `json:"requestedIps,omitempty"`
	ApprovedIPs              []string   `json:"approvedIps,omitempty"`
	Status                   string     `json:"status"`
	ExpiresAt                time.Time  `json:"expiresAt"`
	ApprovedByID             *uuid.UUID `json:"approvedById,omitempty"`
	ApprovedAt               *time.Time `json:"approvedAt,omitempty"`
	RejectedByID             *uuid.UUID `json:"rejectedById,omitempty"`
	RejectionReason          *string    `json:"rejectionReason,omitempty"`
	RejectedAt               *time.Time `json:"rejectedAt,omitempty"`
	CancelledAt              *time.Time `json:"cancelledAt,omitempty"`
	SupportGrantID           *uuid.UUID `json:"supportGrantId,omitempty"`
	CreatedAt                time.Time  `json:"createdAt"`
}

// EffectiveStatus returns the dynamic status of the access request, lazily mapping expired pending requests.
func (r *AccessRequest) EffectiveStatus() string {
	if r.Status == AccessRequestStatusPending && time.Now().After(r.ExpiresAt) {
		return AccessRequestStatusExpired
	}
	return r.Status
}

// CreateAccessRequestInput contains the parameters required to submit a new access request.
type CreateAccessRequestInput struct {
	TargetService   string   `json:"targetService,omitempty"`
	Reason          string   `json:"reason" validate:"required,min=3,max=1000"`
	DurationMinutes int      `json:"durationMinutes" validate:"required,min=1,max=1440"`
	Scope           string   `json:"scope,omitempty" validate:"omitempty,max=64"`
	WhitelistedIPs  []string `json:"whitelistedIps,omitempty"`
}

// ApproveAccessRequestInput contains optional override parameters when approving an access request.
type ApproveAccessRequestInput struct {
	DurationMinutes int      `json:"durationMinutes,omitempty" validate:"omitempty,min=1,max=1440"`
	Scope           string   `json:"scope,omitempty" validate:"omitempty,max=64"`
	WhitelistedIPs  []string `json:"whitelistedIps,omitempty"`
}

// RejectAccessRequestInput contains the rejection reason when denying an access request.
type RejectAccessRequestInput struct {
	RejectionReason string `json:"rejectionReason" validate:"required,min=3,max=1000"`
}

// ApproveAccessRequestResult encapsulates the atomic outcome of approving an access request.
// Note: RawToken is returned strictly once to the approving administrator and is never persisted.
type ApproveAccessRequestResult struct {
	Request   *AccessRequest `json:"request"`
	Grant     *SupportGrant  `json:"grant"`
	RawToken  string         `json:"rawToken"`
	ExpiresAt time.Time      `json:"expiresAt"`
}
