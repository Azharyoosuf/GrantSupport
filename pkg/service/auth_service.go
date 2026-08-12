package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"grantsupport/ent"
	"grantsupport/pkg/cache"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/domain/projections"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
)

// Security constants for authentication policies.
const (
	MaxLoginAttempts           = 5
	LockoutDuration            = 15 * time.Minute
	VerificationGracePeriod    = 24 * time.Hour
	PasswordResetTokenDuration = 1 * time.Hour
)

// Auth Domain Errors
var (
	ErrAuthFailed        = errors.New("AUTH_FAILED: Invalid credentials")
	ErrAccountLocked     = errors.New("AUTH_LOCKED: Account is locked due to repeated failed attempts")
	ErrAccountSuspended  = errors.New("AUTH_FAILED: Account suspended")
	ErrPendingInvite     = errors.New("AUTH_FAILED: Pending invitation, please use invite link")
	ErrVerificationFailed = errors.New("VERIFICATION_FAILED: Invalid or expired token")
	ErrResetFailed        = errors.New("RESET_FAILED: Invalid or expired reset token")
	ErrInvitationInvalid  = errors.New("INVITATION_INVALID: Invitation token is invalid")
	ErrInvitationExpired  = errors.New("INVITATION_EXPIRED: Invitation token has expired")
	ErrSupportGrantInvalid = errors.New("SUPPORT_GRANT_INVALID: Support grant token is invalid or expired")
)

// LoginResult contains output metrics from a successful login sequence.
type LoginResult struct {
	AccessToken   string                      `json:"access_token,omitempty"`
	MfaRequired   bool                        `json:"mfa_required"`
	UserID        uuid.UUID                   `json:"user_id,omitempty"`
	Email         string                      `json:"email,omitempty"`
	InstitutionID uuid.UUID                   `json:"institution_id,omitempty"`
	Token         string                      `json:"token,omitempty"`
	User          *projections.UserSafeProfile `json:"user,omitempty"`
}

// WebAuthnUserWrapper satisfies the webauthn.User interface.
type WebAuthnUserWrapper struct {
	ID          uuid.UUID
	Email       string
	Name        string
	Credentials []webauthn.Credential
}

func (u *WebAuthnUserWrapper) WebAuthnID() []byte {
	return u.ID[:]
}

func (u *WebAuthnUserWrapper) WebAuthnName() string {
	return u.Email
}

func (u *WebAuthnUserWrapper) WebAuthnDisplayName() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

func (u *WebAuthnUserWrapper) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u *WebAuthnUserWrapper) WebAuthnIcon() string {
	return ""
}

// AuthService coordinates account registration, authentication, MFA, password resets, and support grants.
type AuthService struct {
	userRepo         *repository.UserRepository
	instRepo         *repository.InstitutionRepository
	supportGrantRepo *repository.SupportGrantRepository
	auditService     *SecurityAuditService
	queueService     *QueueService
	valkey           *cache.ValkeyClient
	webAuthn         *webauthn.WebAuthn
}

// NewAuthService constructs an AuthService instance with injected dependencies.
func NewAuthService(
	userRepo *repository.UserRepository,
	instRepo *repository.InstitutionRepository,
	supportGrantRepo *repository.SupportGrantRepository,
	auditService *SecurityAuditService,
	queueService *QueueService,
	valkey *cache.ValkeyClient,
) *AuthService {
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}
	rpOrigin := os.Getenv("WEBAUTHN_ORIGIN")
	origins := []string{"http://localhost:3000", "http://localhost:8080", "https://app.tenantpro.com"}
	if rpOrigin != "" {
		origins = append(origins, rpOrigin)
	}

	wconfig := &webauthn.Config{
		RPDisplayName: "TenantPro ERP",
		RPID:          rpID,
		RPOrigins:     origins,
	}
	wa, _ := webauthn.New(wconfig)

	return &AuthService{
		userRepo:         userRepo,
		instRepo:         instRepo,
		supportGrantRepo: supportGrantRepo,
		auditService:     auditService,
		queueService:     queueService,
		valkey:           valkey,
		webAuthn:         wa,
	}
}

// RegisterInstitutionInput captures details required for tenant self-service onboarding.
type RegisterInstitutionInput struct {
	Name       string `json:"name"`
	Domain     string `json:"domain"`
	AdminEmail string `json:"admin_email"`
	Password   string `json:"password"`
}

// RegisterInstitution registers a new institution and its primary administrator atomically.
func (s *AuthService) RegisterInstitution(ctx context.Context, input RegisterInstitutionInput) (*repository.RegisterResult, error) {
	existingDomain, err := s.instRepo.FindByDomain(ctx, input.Domain)
	if err == nil && existingDomain != nil {
		return nil, errors.New("REGISTRATION_FAILED: Domain already registered")
	}

	existingUser, err := s.userRepo.FindByEmail(ctx, input.AdminEmail)
	if err == nil && existingUser != nil {
		return nil, errors.New("REGISTRATION_FAILED: Email already in use")
	}

	passwordHash, err := security.HashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}
	rawToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])
	expiresAt := time.Now().Add(24 * time.Hour)

	repoInput := repository.RegisterInput{
		Name:           input.Name,
		Domain:         input.Domain,
		AdminEmail:     input.AdminEmail,
		PasswordHash:   passwordHash,
		TokenHash:      tokenHash,
		TokenExpiresAt: expiresAt,
	}

	result, err := s.instRepo.RegisterInstitutionAndAdmin(ctx, repoInput)
	if err != nil {
		return nil, err
	}

	if s.queueService != nil {
		_ = s.queueService.SendEmail(ctx, input.AdminEmail, "Verify Your TenantPro Account", fmt.Sprintf("Verification code: %s", rawToken))
	}

	return result, nil
}

// Login authenticates a user via email and password, enforcing failed login lockouts and MFA checks.
func (s *AuthService) Login(ctx context.Context, email, password, ip, userAgent string) (*LoginResult, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, ErrAuthFailed
	}

	now := time.Now()
	if user.LockoutUntil != nil && user.LockoutUntil.After(now) {
		remainingMin := int(math.Ceil(user.LockoutUntil.Sub(now).Minutes()))
		return nil, fmt.Errorf("AUTH_LOCKED: Account is locked. Try again in %d minute(s)", remainingMin)
	}

	if user.Status == domain.UserStatusPendingVerification {
		if now.Sub(user.CreatedAt) > VerificationGracePeriod {
			return nil, errors.New("AUTH_FAILED: Please verify your email to continue")
		}
	}

	if user.Status == domain.UserStatusInactive {
		return nil, ErrAccountSuspended
	}
	if user.Status == domain.UserStatusPendingInvite {
		return nil, ErrPendingInvite
	}

	isMatch, err := security.VerifyPassword(password, user.PasswordHash)
	if err != nil || !isMatch {
		newAttempts := user.FailedLoginAttempts + 1
		var lockoutUntil *time.Time
		if newAttempts >= MaxLoginAttempts {
			t := now.Add(LockoutDuration)
			lockoutUntil = &t
		}

		_ = s.userRepo.UpdateLoginFailures(ctx, user.ID, user.InstitutionID, newAttempts, lockoutUntil)

		if s.auditService != nil {
			_ = s.auditService.LogEvent(ctx, user.InstitutionID, user.ID, SecurityEventLoginFailed, fmt.Sprintf("Failed attempt %d/%d", newAttempts, MaxLoginAttempts), nil)
		}
		return nil, ErrAuthFailed
	}

	// Successful Password Match -> Finalize Login State
	_ = s.userRepo.ResetLoginFailures(ctx, user.ID, user.InstitutionID, ip, userAgent)

	if user.MfaEnabled {
		return &LoginResult{
			MfaRequired:   true,
			UserID:        user.ID,
			Email:         user.Email,
			InstitutionID: user.InstitutionID,
		}, nil
	}

	safeProfile := user.ToSafeProfile()

	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, user.InstitutionID, user.ID, SecurityEventLoginSuccess, "User logged in successfully", nil)
	}

	return &LoginResult{
		MfaRequired:   false,
		UserID:        user.ID,
		Email:         user.Email,
		InstitutionID: user.InstitutionID,
		User:          safeProfile,
	}, nil
}

// RequestPasswordReset creates a password reset token and dispatches a reset link email.
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		return nil // Silent return for privacy security
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}
	rawToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	if err := s.userRepo.CreatePasswordResetToken(ctx, user.ID, user.InstitutionID, tokenHash, time.Now().Add(PasswordResetTokenDuration)); err != nil {
		return err
	}

	if s.queueService != nil {
		_ = s.queueService.SendEmail(ctx, email, "Reset Your Password", fmt.Sprintf("Reset token: %s", rawToken))
	}

	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, user.InstitutionID, user.ID, SecurityEventPasswordResetRequest, "Password reset requested", nil)
	}

	return nil
}

// ResetPassword verifies a password reset token and updates the user's password hash.
func (s *AuthService) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	resetToken, err := s.userRepo.FindPasswordResetToken(ctx, tokenHash)
	if err != nil || resetToken == nil || resetToken.ExpiresAt.Before(time.Now()) {
		return ErrResetFailed
	}

	passwordHash, err := security.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := s.userRepo.UpdatePasswordAndRevokeTokens(ctx, resetToken.UserID, resetToken.InstitutionID, passwordHash); err != nil {
		return err
	}

	_ = s.userRepo.DeletePasswordResetToken(ctx, resetToken.ID)

	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, resetToken.InstitutionID, resetToken.UserID, SecurityEventPasswordResetSuccess, "Password reset successfully", nil)
	}

	return nil
}

// RevokeAllSessions revokes all active sessions for a user by invalidating cache and incrementing token version.
func (s *AuthService) RevokeAllSessions(ctx context.Context, userID, institutionID uuid.UUID) error {
	if err := s.userRepo.RevokeAllSessions(ctx, userID, institutionID); err != nil {
		return err
	}

	if s.valkey != nil && s.valkey.Client != nil {
		key := fmt.Sprintf("cache:%s:user:security:%s", institutionID.String(), userID.String())
		s.valkey.Client.Del(ctx, key)
	}

	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, institutionID, userID, SecurityEventSessionRevoked, "All user sessions revoked", nil)
	}

	return nil
}

// RevokeSpecificSession revokes a specific user session ensuring the caller owns the session or is an administrator.
func (s *AuthService) RevokeSpecificSession(ctx context.Context, callerUserID, institutionID uuid.UUID, sessionIDStr string) error {
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return errors.New("INVALID_SESSION_ID: Session ID format is invalid")
	}

	session, err := s.userRepo.GetSessionByID(ctx, sessionID)
	if err != nil || session == nil {
		return errors.New("SESSION_NOT_FOUND: Session does not exist")
	}

	// IDOR Ownership Guard: Caller must own the target session or be scoped to the same institution
	if session.UserID != callerUserID && session.InstitutionID != institutionID {
		return errors.New("FORBIDDEN: You do not have authorization to revoke this session")
	}

	if err := s.userRepo.DeleteSession(ctx, sessionID); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, institutionID, callerUserID, SecurityEventSessionRevoked, fmt.Sprintf("Revoked session %s", sessionIDStr), nil)
	}

	return nil
}

// AdminUnlockUser resets a user's failed login attempts and clears their lockout timestamp.
func (s *AuthService) AdminUnlockUser(ctx context.Context, targetUserID, authorizedByUserID, institutionID uuid.UUID) error {
	if targetUserID == authorizedByUserID {
		return errors.New("SELF_ACTION_FORBIDDEN: You cannot unlock your own account")
	}

	if err := s.userRepo.ResetLoginFailures(ctx, targetUserID, institutionID, "", ""); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, institutionID, authorizedByUserID, SecurityEventAccountActivated, fmt.Sprintf("Unlocked user account %s", targetUserID), nil)
	}

	return nil
}

// CreateSupportGrant creates a temporary support access token for platform support troubleshooting.
func (s *AuthService) CreateSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int) (string, error) {
	if s.supportGrantRepo == nil {
		return "", errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	// Step 1.5: Enforce server-side duration cap (max 1440 mins / 24 hours)
	if durationMinutes <= 0 || durationMinutes > 1440 {
		return "", errors.New("INVALID_DURATION: Support grant duration must be between 1 and 1440 minutes")
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate support grant token: %w", err)
	}
	randomHex := hex.EncodeToString(tokenBytes)
	rawToken := fmt.Sprintf("%s_%s", institutionID.String(), randomHex)

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	expiresAt := time.Now().Add(time.Duration(durationMinutes) * time.Minute)

	input := &domain.CreateSupportGrantInput{
		InstitutionID: institutionID,
		GrantedByID:   adminUserID,
		TokenHash:     tokenHash,
		ExpiresAt:     expiresAt,
	}

	// Step 1.5: Acquire Valkey Redlock concurrency guard on grant creation
	if s.valkey != nil && s.valkey.LockService != nil {
		lockKey := fmt.Sprintf("lock:grant:%s", institutionID.String())
		err := s.valkey.LockService.WithLock(ctx, lockKey, 10*time.Second, func(txCtx context.Context) error {
			_, err := s.supportGrantRepo.CreateSupportGrant(txCtx, input)
			return err
		})
		if err != nil {
			return "", fmt.Errorf("failed to create support grant under lock: %w", err)
		}
	} else {
		if _, err := s.supportGrantRepo.CreateSupportGrant(ctx, input); err != nil {
			return "", err
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, institutionID, adminUserID, SecurityEventSupportAccessGranted, fmt.Sprintf("Support access grant created for %d minutes", durationMinutes), nil)
	}

	return rawToken, nil
}

// SupportLogin authenticates a platform support engineer using a valid support grant token.
func (s *AuthService) SupportLogin(ctx context.Context, rawToken string, agentUserID uuid.UUID) (*projections.UserSafeProfile, uuid.UUID, string, error) {
	parts := strings.Split(rawToken, "_")
	if len(parts) != 2 {
		return nil, uuid.Nil, "", ErrSupportGrantInvalid
	}

	instID, err := uuid.Parse(parts[0])
	if err != nil {
		return nil, uuid.Nil, "", ErrSupportGrantInvalid
	}

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	if s.supportGrantRepo == nil {
		return nil, uuid.Nil, "", errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	grant, err := s.supportGrantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil || grant == nil || grant.ExpiresAt.Before(time.Now()) {
		return nil, uuid.Nil, "", ErrSupportGrantInvalid
	}

	// Step 1.3: Mark grant as consumed to prevent multi-use token replay
	if err := s.supportGrantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		return nil, uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}

	platformOwner, err := s.userRepo.FindActivePlatformOwnerProfile(ctx)
	if err != nil || platformOwner == nil {
		return nil, uuid.Nil, "", errors.New("SUPPORT_LOGIN_FAILED: Active platform owner not found")
	}

	// Step 1.4: Capture and record real support agent identity in audit logs
	if s.auditService != nil {
		agentIDToLog := agentUserID
		if agentIDToLog == uuid.Nil {
			agentIDToLog = platformOwner.ID
		}
		_ = s.auditService.LogEvent(ctx, instID, agentIDToLog, SecurityEventSupportAccessLoggedIn, fmt.Sprintf("Support login executed by agent %s via active grant", agentIDToLog.String()), nil)
	}

	jwtToken, err := security.GenerateJWT(
		platformOwner.ID.String(),
		instID.String(),
		"SUPPORT_AGENT",
		4*time.Hour,
	)
	if err != nil {
		return nil, uuid.Nil, "", fmt.Errorf("failed to generate support JWT: %w", err)
	}

	return platformOwner, instID, jwtToken, nil
}

// RevokeSupportGrant invalidates all active support grants for an institution.
func (s *AuthService) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	if s.supportGrantRepo == nil {
		return errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if err := s.supportGrantRepo.RevokeAllGrantsForInstitution(ctx, institutionID); err != nil {
		return err
	}

	// Step 1.4: Dispatch SecurityEventSupportAccessRevoked to audit log
	if s.auditService != nil {
		_ = s.auditService.LogEvent(ctx, institutionID, adminUserID, SecurityEventSupportAccessRevoked, "All active support access grants manually revoked by administrator", nil)
	}

	return nil
}

// VerifyEmailToken validates account email verification token.
func (s *AuthService) VerifyEmailToken(ctx context.Context, token string) error {
	sum := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(sum[:])

	record, err := s.userRepo.FindVerificationToken(ctx, tokenHash)
	if err != nil || record == nil {
		return errors.New("INVALID_VERIFICATION_TOKEN: Token not found or already used")
	}
	if record.ExpiresAt.Before(time.Now()) {
		return errors.New("EXPIRED_VERIFICATION_TOKEN: Token has expired")
	}

	userEdge := record.Edges.User
	if userEdge == nil {
		return errors.New("INVALID_VERIFICATION_TOKEN: User record not linked")
	}

	return s.userRepo.VerifyEmailTokenRecord(ctx, record.ID, userEdge.ID, userEdge.Email, userEdge.InstitutionID)
}

// VerifyMfaLogin verifies a 2FA TOTP code during login.
func (s *AuthService) VerifyMfaLogin(ctx context.Context, userID uuid.UUID, code string) (*LoginResult, error) {
	user, err := s.userRepo.FindForMfaBootstrap(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrAuthFailed
	}
	if !user.MfaEnabled || user.MfaSecret == nil || *user.MfaSecret == "" {
		return nil, errors.New("MFA_NOT_ENABLED: MFA is not configured for this account")
	}

	if !totp.Validate(code, *user.MfaSecret) {
		return nil, errors.New("MFA_INVALID_CODE: Provided TOTP code is incorrect or expired")
	}

	jwtToken, err := security.GenerateJWT(user.ID.String(), user.InstitutionID.String(), string(user.Role), 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT after MFA: %w", err)
	}

	userProfile, _ := s.userRepo.FindByID(ctx, user.ID, user.InstitutionID)

	return &LoginResult{
		AccessToken:   jwtToken,
		Token:         jwtToken,
		MfaRequired:   false,
		UserID:        user.ID,
		Email:         user.Email,
		InstitutionID: user.InstitutionID,
		User:          userProfile,
	}, nil
}

// InitiateMfaSetup generates 2FA TOTP secret and QR uri for setup.
func (s *AuthService) InitiateMfaSetup(ctx context.Context, userID uuid.UUID) (string, error) {
	user, err := s.userRepo.FindForMfaBootstrap(ctx, userID)
	if err != nil || user == nil {
		return "", ErrAuthFailed
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TenantPro",
		AccountName: user.Email,
		SecretSize:  20,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	secretStr := key.Secret()
	if err := s.userRepo.SaveMfaSecret(ctx, userID, secretStr); err != nil {
		return "", fmt.Errorf("failed to store MFA secret: %w", err)
	}

	return key.URL(), nil
}

// CompleteMfaSetup verifies TOTP setup code and enables MFA.
func (s *AuthService) CompleteMfaSetup(ctx context.Context, userID uuid.UUID, code string) error {
	user, err := s.userRepo.FindForMfaBootstrap(ctx, userID)
	if err != nil || user == nil {
		return ErrAuthFailed
	}
	if user.MfaSecret == nil || *user.MfaSecret == "" {
		return errors.New("MFA_SETUP_REQUIRED: Call InitiateMfaSetup first")
	}

	if !totp.Validate(code, *user.MfaSecret) {
		return errors.New("MFA_INVALID_CODE: Setup verification code is incorrect")
	}

	return s.userRepo.EnableMfa(ctx, userID)
}

// AcceptInvitation completes invitation registration with password set.
func (s *AuthService) AcceptInvitation(ctx context.Context, token, password string) error {
	sum := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(sum[:])
	resetRecord, err := s.userRepo.FindPasswordResetToken(ctx, tokenHash)
	if err != nil || resetRecord == nil || resetRecord.ExpiresAt.Before(time.Now()) {
		return ErrInvitationInvalid
	}

	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	email := ""
	if resetRecord.Edges.User != nil {
		email = resetRecord.Edges.User.Email
	}

	if err := s.userRepo.AcceptInvitation(ctx, resetRecord.UserID, resetRecord.InstitutionID, passwordHash, email); err != nil {
		return fmt.Errorf("failed to accept invitation: %w", err)
	}

	_ = s.userRepo.DeletePasswordResetToken(ctx, resetRecord.ID)
	return nil
}

// GetUserSessions retrieves active sessions for user.
func (s *AuthService) GetUserSessions(ctx context.Context, userID, institutionID uuid.UUID) ([]*ent.Session, error) {
	return s.userRepo.GetUserSessions(ctx, userID)
}

// GeneratePasskeyRegisterOptions creates WebAuthn registration options.
func (s *AuthService) GeneratePasskeyRegisterOptions(ctx context.Context, userID uuid.UUID) (interface{}, error) {
	user, err := s.userRepo.FindByID(ctx, userID, uuid.Nil)
	if err != nil || user == nil {
		return nil, ErrAuthFailed
	}

	wUser := &WebAuthnUserWrapper{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Email,
	}

	options, sessionData, err := s.webAuthn.BeginRegistration(wUser)
	if err != nil {
		return nil, fmt.Errorf("webauthn begin registration failed: %w", err)
	}

	if s.valkey != nil && s.valkey.Client != nil {
		sessBytes, _ := json.Marshal(sessionData)
		key := fmt.Sprintf("passkey:reg:session:%s", userID.String())
		_ = s.valkey.Client.Set(ctx, key, string(sessBytes), 5*time.Minute).Err()
	}

	return options, nil
}

// VerifyPasskeyRegister verifies WebAuthn registration.
func (s *AuthService) VerifyPasskeyRegister(ctx context.Context, userID uuid.UUID, response interface{}) error {
	user, err := s.userRepo.FindByID(ctx, userID, uuid.Nil)
	if err != nil || user == nil {
		return ErrAuthFailed
	}

	var sessionData webauthn.SessionData
	if s.valkey != nil && s.valkey.Client != nil {
		key := fmt.Sprintf("passkey:reg:session:%s", userID.String())
		sessStr, err := s.valkey.Client.Get(ctx, key).Result()
		if err == nil && sessStr != "" {
			_ = json.Unmarshal([]byte(sessStr), &sessionData)
		}
	}

	req, ok := response.(*http.Request)
	if !ok {
		return errors.New("INVALID_WEBAUTHN_REQUEST: Expected *http.Request")
	}

	wUser := &WebAuthnUserWrapper{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Email,
	}

	credential, err := s.webAuthn.FinishRegistration(wUser, sessionData, req)
	if err != nil {
		return fmt.Errorf("webauthn finish registration failed: %w", err)
	}

	credID := base64.StdEncoding.EncodeToString(credential.ID)
	pubKey := base64.StdEncoding.EncodeToString(credential.PublicKey)

	_, err = s.userRepo.CreatePasskey(ctx, userID, credID, pubKey, int64(credential.Authenticator.SignCount))
	if err != nil {
		return fmt.Errorf("failed to save passkey credential: %w", err)
	}

	return nil
}

// GeneratePasskeyLoginOptions creates WebAuthn assertion options.
func (s *AuthService) GeneratePasskeyLoginOptions(ctx context.Context, email string) (interface{}, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, ErrAuthFailed
	}

	credIDs, _ := s.userRepo.FindPasskeysByUserID(ctx, user.ID)
	var userCreds []webauthn.Credential
	for _, cid := range credIDs {
		rawID, _ := base64.StdEncoding.DecodeString(cid)
		if len(rawID) > 0 {
			userCreds = append(userCreds, webauthn.Credential{ID: rawID})
		}
	}

	wUser := &WebAuthnUserWrapper{
		ID:          user.ID,
		Email:       user.Email,
		Name:        user.Email,
		Credentials: userCreds,
	}

	options, sessionData, err := s.webAuthn.BeginLogin(wUser)
	if err != nil {
		return nil, fmt.Errorf("webauthn begin login failed: %w", err)
	}

	if s.valkey != nil && s.valkey.Client != nil {
		sessBytes, _ := json.Marshal(sessionData)
		key := fmt.Sprintf("passkey:login:session:%s", user.ID.String())
		_ = s.valkey.Client.Set(ctx, key, string(sessBytes), 5*time.Minute).Err()
	}

	return options, nil
}

// VerifyPasskeyLogin verifies WebAuthn assertion login.
func (s *AuthService) VerifyPasskeyLogin(ctx context.Context, response interface{}) (*LoginResult, error) {
	req, ok := response.(*http.Request)
	if !ok {
		return nil, errors.New("INVALID_WEBAUTHN_REQUEST: Expected *http.Request")
	}

	userIDStr := req.Header.Get("X-User-ID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, ErrAuthFailed
	}

	user, err := s.userRepo.FindByID(ctx, userID, uuid.Nil)
	if err != nil || user == nil {
		return nil, ErrAuthFailed
	}

	var sessionData webauthn.SessionData
	if s.valkey != nil && s.valkey.Client != nil {
		key := fmt.Sprintf("passkey:login:session:%s", userID.String())
		sessStr, err := s.valkey.Client.Get(ctx, key).Result()
		if err == nil && sessStr != "" {
			_ = json.Unmarshal([]byte(sessStr), &sessionData)
		}
	}

	credIDs, _ := s.userRepo.FindPasskeysByUserID(ctx, user.ID)
	var userCreds []webauthn.Credential
	for _, cid := range credIDs {
		rawID, _ := base64.StdEncoding.DecodeString(cid)
		if len(rawID) > 0 {
			userCreds = append(userCreds, webauthn.Credential{ID: rawID})
		}
	}

	wUser := &WebAuthnUserWrapper{
		ID:          user.ID,
		Email:       user.Email,
		Name:        user.Email,
		Credentials: userCreds,
	}

	credential, err := s.webAuthn.FinishLogin(wUser, sessionData, req)
	if err != nil {
		return nil, fmt.Errorf("webauthn finish login failed: %w", err)
	}

	credIDStr := base64.StdEncoding.EncodeToString(credential.ID)
	if pk, err := s.userRepo.FindPasskeyByCredID(ctx, credIDStr); err == nil && pk != nil {
		_ = s.userRepo.UpdatePasskeyCounter(ctx, pk.ID, int64(credential.Authenticator.SignCount))
	}

	return &LoginResult{
		MfaRequired:   false,
		UserID:        user.ID,
		Email:         user.Email,
		InstitutionID: user.InstitutionID,
		User:          user,
	}, nil
}

