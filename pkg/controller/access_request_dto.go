package controller

// CreateAccessRequestPayload represents input for submitting a new access request.
type CreateAccessRequestPayload struct {
	TargetService   string   `json:"targetService" validate:"omitempty,max=128"`
	Reason          string   `json:"reason" validate:"required,min=3,max=1000"`
	DurationMinutes int      `json:"durationMinutes" validate:"required,min=1,max=1440"`
	Scope           string   `json:"scope" validate:"omitempty,max=64"`
	WhitelistedIPs  []string `json:"whitelistedIps" validate:"omitempty"`
}

// ApproveAccessRequestPayload represents optional input overrides when approving an access request.
type ApproveAccessRequestPayload struct {
	DurationMinutes int      `json:"durationMinutes" validate:"omitempty,min=1,max=1440"`
	Scope           string   `json:"scope" validate:"omitempty,max=64"`
	WhitelistedIPs  []string `json:"whitelistedIps" validate:"omitempty"`
}

// RejectAccessRequestPayload represents the rejection reason when denying a request.
type RejectAccessRequestPayload struct {
	RejectionReason string `json:"rejectionReason" validate:"required,min=3,max=1000"`
}
