package controller

// GrantSupportInput captures support delegation duration, scopes, and IP restrictions.
type GrantSupportInput struct {
	DurationMinutes int      `json:"durationMinutes" validate:"gte=1,lte=1440"`
	Scope           string   `json:"scope,omitempty" validate:"omitempty,max=64"`
	WhitelistedIPs  []string `json:"whitelistedIps,omitempty"`
}

// SupportLoginInput captures support token payload and explicit agent UUID.
type SupportLoginInput struct {
	Token   string `json:"token" validate:"required"`
	AgentID string `json:"agentId,omitempty" validate:"omitempty,uuid"`
}


