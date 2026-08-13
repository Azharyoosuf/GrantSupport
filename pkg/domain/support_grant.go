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
