package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/ent/supportgrant"
	"grantsupport/pkg/domain"
)

type SupportGrantRepository struct {
	*BaseRepository
}

func NewSupportGrantRepository(base *BaseRepository) *SupportGrantRepository {
	return &SupportGrantRepository{BaseRepository: base}
}

func (r *SupportGrantRepository) CreateSupportGrant(ctx context.Context, data *domain.CreateSupportGrantInput) (*ent.SupportGrant, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	builder := client.SupportGrant.Create().
		SetInstitutionID(data.InstitutionID).
		SetGrantedByID(data.GrantedByID).
		SetTokenHash(data.TokenHash).
		SetExpiresAt(data.ExpiresAt)

	if data.Scope != "" {
		builder.SetScope(data.Scope)
	}
	if len(data.WhitelistedIPs) > 0 {
		builder.SetWhitelistedIps(data.WhitelistedIPs)
	}

	grant, err := builder.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create support grant: %w", err)
	}
	return grant, nil
}

func (r *SupportGrantRepository) FindActiveGrantByTokenHash(ctx context.Context, tokenHash string) (*ent.SupportGrant, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	grant, err := client.SupportGrant.Query().
		Where(
			supportgrant.TokenHash(tokenHash),
			supportgrant.IsUsed(false),           // Enforce single-use check
			supportgrant.ExpiresAtGT(time.Now()), // strictly check expiration boundary
		).
		Select(
			supportgrant.FieldID,
			supportgrant.FieldInstitutionID,
			supportgrant.FieldGrantedByID,
			supportgrant.FieldTokenHash,
			supportgrant.FieldExpiresAt,
			supportgrant.FieldIsUsed,
			supportgrant.FieldScope,
			supportgrant.FieldCreatedAt,
		).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("failed to query support grant: %w", err)
	}
	if ent.IsNotFound(err) {
		return nil, nil
	}
	return grant, nil
}

var ErrGrantAlreadyUsed = errors.New("GRANT_ALREADY_USED: Support grant has already been consumed or is invalid")

// MarkGrantAsUsed flags a support grant token as consumed atomically using a conditional predicate (is_used = false).
func (r *SupportGrantRepository) MarkGrantAsUsed(ctx context.Context, grantID uuid.UUID) error {
	client, err := r.GetClient(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	affected, err := client.SupportGrant.Update().
		Where(
			supportgrant.ID(grantID),
			supportgrant.IsUsed(false),
		).
		SetIsUsed(true).
		SetUsedAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to mark support grant as used: %w", err)
	}
	if affected == 0 {
		return ErrGrantAlreadyUsed
	}
	return nil
}

func (r *SupportGrantRepository) RevokeAllGrantsForInstitution(ctx context.Context, institutionID uuid.UUID) error {
	client, err := r.GetClient(ctx)
	if err != nil {
		return err
	}

	// Revoke all by setting expires_at to now
	_, err = client.SupportGrant.Update().
		Where(supportgrant.InstitutionID(institutionID)).
		SetExpiresAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to revoke support grants: %w", err)
	}
	return nil
}
