package domain

import (
	"time"

	"github.com/google/uuid"
)

type CreateSupportGrantInput struct {
	InstitutionID  uuid.UUID `json:"institution_id"`
	GrantedByID    uuid.UUID `json:"granted_by_id"`
	TokenHash      string    `json:"token_hash"`
	ExpiresAt      time.Time `json:"expires_at"`
	Scope          string    `json:"scope,omitempty"`
	WhitelistedIPs []string  `json:"whitelisted_ips,omitempty"`
}

// SupportGrant represents a delegated support access grant entity.
type SupportGrant struct {
	ID             uuid.UUID  `json:"id"`
	InstitutionID  uuid.UUID  `json:"institution_id"`
	GrantedByID    uuid.UUID  `json:"granted_by_id"`
	UsedByID       *uuid.UUID `json:"used_by_id,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	IsUsed         bool       `json:"is_used"`
	UsedAt         *time.Time `json:"used_at,omitempty"`
	Scope          string     `json:"scope"`
	WhitelistedIPs []string   `json:"whitelisted_ips,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ActiveSession represents an active delegated support session derived from an active redeemed grant.
type ActiveSession struct {
	GrantID          uuid.UUID `json:"grant_id"`
	InstitutionID    uuid.UUID `json:"institution_id"`
	GrantedByID      uuid.UUID `json:"granted_by_id"`
	UsedByID         uuid.UUID `json:"used_by_id"`
	Scope            string    `json:"scope"`
	WhitelistedIPs   []string  `json:"whitelisted_ips,omitempty"`
	UsedAt           time.Time `json:"used_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RemainingSeconds int64     `json:"remaining_seconds"`
}
