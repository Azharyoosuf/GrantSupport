package controller

// RegisterInstitutionInput captures request payload for institution self-onboarding.
type RegisterInstitutionInput struct {
	Name       string `json:"name" validate:"required,min=3"`
	Domain     string `json:"domain" validate:"required,min=3"`
	AdminEmail string `json:"adminEmail" validate:"required,email"`
	Password   string `json:"password" validate:"required,min=8"`
}

// LoginInput captures authentication credentials.
type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// MfaVerifyInput captures 2FA verification token payload.
type MfaVerifyInput struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Code   string `json:"code" validate:"required,len=6"`
}

// PasswordResetInput captures token and new password for reset.
type PasswordResetInput struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

// ForgotPasswordInput captures email for password reset request.
type ForgotPasswordInput struct {
	Email string `json:"email" validate:"required,email"`
}

// GrantSupportInput captures support delegation duration request.
type GrantSupportInput struct {
	DurationMinutes int `json:"durationMinutes" validate:"gte=1,lte=1440"`
}

// SupportLoginInput captures support token payload.
type SupportLoginInput struct {
	Token string `json:"token" validate:"required"`
}

// PasskeyVerifyRegisterInput captures passkey registration credential payload.
type PasskeyVerifyRegisterInput struct {
	ID           string `json:"id" validate:"required"`
	RawID        string `json:"rawId" validate:"required"`
	Type         string `json:"type" validate:"required"`
	Response     any    `json:"response"`
	Mock         bool   `json:"mock"`
	CredentialID string `json:"credentialId"`
	PublicKey    string `json:"publicKey"`
}

// PasskeyLoginOptionsInput captures passkey login options request payload.
type PasskeyLoginOptionsInput struct {
	Email string `json:"email" validate:"required,email"`
}

// PasskeyLoginVerifyInput captures passkey assertion verification payload.
type PasskeyLoginVerifyInput struct {
	Email     string `json:"email" validate:"required,email"`
	Assertion any    `json:"assertion"`
}

// VerifyMfaInput captures MFA verification payload.
type VerifyMfaInput struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Code   string `json:"code" validate:"required"`
}

// CompleteMfaInput captures MFA completion payload.
type CompleteMfaInput struct {
	Code string `json:"code" validate:"required"`
}

// AcceptInviteInput captures invitation acceptance payload.
type AcceptInviteInput struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

