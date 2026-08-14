package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/webhook"
)

var (
	ErrSupportGrantInvalid = errors.New("SUPPORT_GRANT_INVALID: Invalid or expired support grant token")
	ErrSupportGrantExpired = errors.New("SUPPORT_GRANT_EXPIRED: Support grant token has expired")
)

type GrantSupportService struct {
	supportGrantRepo  *repository.SupportGrantRepository
	auditRepo         *repository.SecurityAuditRepository
	lockStore         ports.LockStore
	revocationStore   ports.RevocationStore
	webhookDispatcher *webhook.WebhookDispatcher
}

func NewGrantSupportService(
	supportGrantRepo *repository.SupportGrantRepository,
	auditRepo *repository.SecurityAuditRepository,
	lockStore ports.LockStore,
) *GrantSupportService {
	return &GrantSupportService{
		supportGrantRepo: supportGrantRepo,
		auditRepo:        auditRepo,
		lockStore:        lockStore,
	}
}

// SetRevocationStore attaches a RevocationStore for active session invalidation.
func (s *GrantSupportService) SetRevocationStore(r ports.RevocationStore) {
	s.revocationStore = r
}

// SetWebhookDispatcher attaches an optional WebhookDispatcher for lifecycle event notifications.
func (s *GrantSupportService) SetWebhookDispatcher(d *webhook.WebhookDispatcher) {
	s.webhookDispatcher = d
}

// CreateSupportGrant creates a temporary support access token with default FULL_ACCESS scope.
func (s *GrantSupportService) CreateSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int) (string, error) {
	return s.CreateSupportGrantScoped(ctx, institutionID, adminUserID, durationMinutes, "FULL_ACCESS", nil)
}

// CreateSupportGrantScoped creates a temporary support access token with granular scope and IP restrictions.
func (s *GrantSupportService) CreateSupportGrantScoped(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int, scope string, whitelistedIPs []string) (string, error) {
	if s.supportGrantRepo == nil {
		return "", errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if durationMinutes <= 0 || durationMinutes > 1440 {
		return "", errors.New("INVALID_DURATION: Support grant duration must be between 1 and 1440 minutes")
	}

	if scope == "" {
		scope = "FULL_ACCESS"
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
		InstitutionID:  institutionID,
		GrantedByID:    adminUserID,
		TokenHash:      tokenHash,
		ExpiresAt:      expiresAt,
		Scope:          scope,
		WhitelistedIPs: whitelistedIPs,
	}

	if s.lockStore != nil {
		lockKey := fmt.Sprintf("lock:grant:%s", institutionID.String())
		err := s.lockStore.WithLock(ctx, lockKey, 10*time.Second, func(txCtx context.Context) error {
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

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_GRANTED", fmt.Sprintf("Support access grant created for %d minutes with scope %s", durationMinutes, scope), nil)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.DispatchAsync(webhook.NewWebhookEvent(
			"grant.created",
			institutionID.String(),
			adminUserID.String(),
			map[string]any{
				"duration_minutes": durationMinutes,
				"scope":            scope,
				"expires_at":       expiresAt.Unix(),
				"whitelisted_ips":  whitelistedIPs,
			},
		))
	}

	return rawToken, nil
}

// SupportLogin authenticates a support agent using a valid support grant token and issues an RS256 JWT access token.
func (s *GrantSupportService) SupportLogin(ctx context.Context, rawToken string, agentUserID uuid.UUID) (uuid.UUID, string, error) {
	if agentUserID == uuid.Nil {
		return uuid.Nil, "", errors.New("AGENT_ID_REQUIRED: Explicit agentId UUID must be provided")
	}

	parts := strings.Split(rawToken, "_")
	if len(parts) != 2 {
		return uuid.Nil, "", ErrSupportGrantInvalid
	}

	instID, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, "", ErrSupportGrantInvalid
	}

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	if s.supportGrantRepo == nil {
		return uuid.Nil, "", errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	grant, err := s.supportGrantRepo.FindActiveGrantByTokenHash(ctx, tokenHash)
	if err != nil || grant == nil || grant.ExpiresAt.Before(time.Now()) {
		return uuid.Nil, "", ErrSupportGrantInvalid
	}

	// Defense-in-depth: token_hash uniqueness makes a mismatch impossible under the current token format,
	// but this check ensures any future change to token generation cannot silently reintroduce a cross-institution trust gap.
	if grant.InstitutionID != instID {
		if s.auditRepo != nil {
			_, _ = s.auditRepo.LogSecurityEvent(ctx, grant.InstitutionID, agentUserID,
				"SUPPORT_LOGIN_INSTITUTION_MISMATCH",
				fmt.Sprintf("Token-derived institution ID %s did not match grant record institution ID %s — possible token tampering", instID, grant.InstitutionID),
				nil)
		}
		return uuid.Nil, "", ErrSupportGrantInvalid
	}

	if err := s.supportGrantRepo.MarkGrantAsUsed(ctx, grant.ID, agentUserID); err != nil {
		if errors.Is(err, repository.ErrGrantAlreadyUsed) {
			return uuid.Nil, "", ErrSupportGrantInvalid
		}
		return uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, grant.InstitutionID, agentUserID, "SUPPORT_ACCESS_LOGGED_IN", fmt.Sprintf("Support login executed by agent %s via active grant with scope %s", agentUserID.String(), grant.Scope), nil)
	}

	currentVer := 1
	if s.revocationStore != nil {
		if ver, err := s.revocationStore.GetUserTokenVersion(ctx, grant.InstitutionID.String(), agentUserID.String()); err == nil && ver >= 1 {
			currentVer = ver
		}
	}

	// Security/Lifecycle Invariant: The support session cannot outlive the expiration of the grant from which it was issued.
	jwtToken, err := security.GenerateJWTWithExpiresAt(
		agentUserID.String(),
		grant.InstitutionID.String(),
		"SUPPORT_AGENT",
		grant.Scope,
		currentVer,
		grant.ExpiresAt,
	)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to generate support JWT: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.DispatchAsync(webhook.NewWebhookEvent(
			"grant.claimed",
			grant.InstitutionID.String(),
			agentUserID.String(),
			map[string]any{
				"grant_id": grant.ID.String(),
				"scope":    grant.Scope,
				"used_at":  time.Now().Unix(),
			},
		))
	}

	return grant.InstitutionID, jwtToken, nil
}

// RevokeSupportGrant invalidates all active support grants for an institution and terminates active support-agent sessions.
func (s *GrantSupportService) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	if s.supportGrantRepo == nil {
		return errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	agentIDs, err := s.supportGrantRepo.RevokeAllGrantsForInstitution(ctx, institutionID)
	if err != nil {
		return err
	}

	// Invalidate active JWT sessions for all support agents who claimed grants in this institution
	if s.revocationStore != nil {
		for _, agentID := range agentIDs {
			currentVer := 1
			if ver, err := s.revocationStore.GetUserTokenVersion(ctx, institutionID.String(), agentID.String()); err == nil && ver >= 1 {
				currentVer = ver
			}
			if err := s.revocationStore.RevokeUserSessions(ctx, institutionID.String(), agentID.String(), currentVer+1); err != nil {
				return fmt.Errorf("failed to invalidate active support session for agent %s: %w", agentID, err)
			}
		}
	}

	if s.auditRepo != nil {
		desc := fmt.Sprintf("All active support access grants manually revoked by administrator (invalidated %d active support agent session(s))", len(agentIDs))
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", desc, nil)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.DispatchAsync(webhook.NewWebhookEvent(
			"grant.revoked",
			institutionID.String(),
			adminUserID.String(),
			map[string]any{
				"revoked_at":           time.Now().Unix(),
				"sessions_invalidated": len(agentIDs),
			},
		))
	}

	return nil
}

// SupportLogout terminates an active support agent session by invalidating their token version.
func (s *GrantSupportService) SupportLogout(ctx context.Context, institutionID, agentUserID uuid.UUID) error {
	if s.revocationStore != nil {
		currentVer := 1
		if ver, err := s.revocationStore.GetUserTokenVersion(ctx, institutionID.String(), agentUserID.String()); err == nil && ver >= 1 {
			currentVer = ver
		}
		if err := s.revocationStore.RevokeUserSessions(ctx, institutionID.String(), agentUserID.String(), currentVer+1); err != nil {
			return fmt.Errorf("failed to revoke agent session: %w", err)
		}
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, agentUserID, "SUPPORT_ACCESS_LOGGED_OUT", fmt.Sprintf("Support agent %s voluntarily logged out of support session", agentUserID.String()), nil)
	}

	return nil
}
