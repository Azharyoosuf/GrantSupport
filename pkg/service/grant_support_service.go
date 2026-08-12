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
	"grantsupport/pkg/cache"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
)

var (
	ErrSupportGrantInvalid = errors.New("SUPPORT_GRANT_INVALID: Invalid or expired support grant token")
	ErrSupportGrantExpired = errors.New("SUPPORT_GRANT_EXPIRED: Support grant token has expired")
	ErrLicenseLimitExceeded = errors.New("LICENSE_LIMIT_EXCEEDED: Maximum agent seat limit reached for your plan tier")
)

type GrantSupportService struct {
	supportGrantRepo *repository.SupportGrantRepository
	auditRepo        *repository.SecurityAuditRepository
	valkey           *cache.ValkeyClient
}

func NewGrantSupportService(
	supportGrantRepo *repository.SupportGrantRepository,
	auditRepo *repository.SecurityAuditRepository,
	valkey *cache.ValkeyClient,
) *GrantSupportService {
	return &GrantSupportService{
		supportGrantRepo: supportGrantRepo,
		auditRepo:        auditRepo,
		valkey:           valkey,
	}
}

// CreateSupportGrant creates a temporary support access token for platform support troubleshooting.
func (s *GrantSupportService) CreateSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID, durationMinutes int) (string, error) {
	if s.supportGrantRepo == nil {
		return "", errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

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

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_GRANTED", fmt.Sprintf("Support access grant created for %d minutes", durationMinutes), nil)
	}

	return rawToken, nil
}

// SupportLogin authenticates a support agent using a valid support grant token and issues an RS256 JWT access token.
func (s *GrantSupportService) SupportLogin(ctx context.Context, rawToken string, agentUserID uuid.UUID) (uuid.UUID, string, error) {
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

	if err := s.supportGrantRepo.MarkGrantAsUsed(ctx, grant.ID); err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to consume support grant: %w", err)
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, instID, agentUserID, "SUPPORT_ACCESS_LOGGED_IN", fmt.Sprintf("Support login executed by agent %s via active grant", agentUserID.String()), nil)
	}

	jwtToken, err := security.GenerateJWT(
		agentUserID.String(),
		instID.String(),
		"SUPPORT_AGENT",
		4*time.Hour,
	)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to generate support JWT: %w", err)
	}

	return instID, jwtToken, nil
}

// RevokeSupportGrant invalidates all active support grants for an institution.
func (s *GrantSupportService) RevokeSupportGrant(ctx context.Context, institutionID, adminUserID uuid.UUID) error {
	if s.supportGrantRepo == nil {
		return errors.New("SUPPORT_GRANT_UNAVAILABLE: SupportGrantRepository not configured")
	}

	if err := s.supportGrantRepo.RevokeAllGrantsForInstitution(ctx, institutionID); err != nil {
		return err
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.LogSecurityEvent(ctx, institutionID, adminUserID, "SUPPORT_ACCESS_REVOKED", "All active support access grants manually revoked by administrator", nil)
	}

	return nil
}
