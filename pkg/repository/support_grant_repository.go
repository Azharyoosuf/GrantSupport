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
	} else {
		builder.SetWhitelistedIps([]string{})
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
			supportgrant.FieldWhitelistedIps,
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

// MarkGrantAsUsed flags a support grant token as consumed atomically using a conditional predicate (is_used = false), recording the redeeming agent user ID.
func (r *SupportGrantRepository) MarkGrantAsUsed(ctx context.Context, grantID uuid.UUID, agentUserID ...uuid.UUID) error {
	client, err := r.GetClient(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	builder := client.SupportGrant.Update().
		Where(
			supportgrant.ID(grantID),
			supportgrant.IsUsed(false),
		).
		SetIsUsed(true).
		SetUsedAt(now)

	if len(agentUserID) > 0 && agentUserID[0] != uuid.Nil {
		builder.SetUsedByID(agentUserID[0])
	}

	affected, err := builder.Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to mark support grant as used: %w", err)
	}
	if affected == 0 {
		return ErrGrantAlreadyUsed
	}
	return nil
}

// RevokeAllGrantsForInstitution expires all unredeemed support grants for an institution and returns the distinct agent user IDs whose sessions were active.
func (r *SupportGrantRepository) RevokeAllGrantsForInstitution(ctx context.Context, institutionID uuid.UUID) ([]uuid.UUID, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	// Query active support agent user IDs that consumed grants for this institution
	// whose grant authorization window has not yet passed (i.e. whose session is still active)
	now := time.Now()
	usedGrants, err := client.SupportGrant.Query().
		Where(
			supportgrant.InstitutionID(institutionID),
			supportgrant.IsUsed(true),
			supportgrant.UsedByIDNotNil(),
			supportgrant.ExpiresAtGT(now),
		).
		Select(supportgrant.FieldUsedByID).
		All(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("failed to query active support grant agents: %w", err)
	}

	agentMap := make(map[uuid.UUID]struct{})
	for _, g := range usedGrants {
		if g.UsedByID != nil && *g.UsedByID != uuid.Nil {
			agentMap[*g.UsedByID] = struct{}{}
		}
	}

	agentIDs := make([]uuid.UUID, 0, len(agentMap))
	for id := range agentMap {
		agentIDs = append(agentIDs, id)
	}

	// Revoke all unredeemed grants by setting expires_at to now
	_, err = client.SupportGrant.Update().
		Where(supportgrant.InstitutionID(institutionID)).
		SetExpiresAt(time.Now()).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke support grants: %w", err)
	}

	return agentIDs, nil
}

var ErrGrantNotFound = errors.New("GRANT_NOT_FOUND: Support grant not found or does not belong to this institution")

// FindActiveSessionsByInstitution retrieves all currently active redeemed support grants for an institution.
func (r *SupportGrantRepository) FindActiveSessionsByInstitution(ctx context.Context, institutionID uuid.UUID) ([]*ent.SupportGrant, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	grants, err := client.SupportGrant.Query().
		Where(
			supportgrant.InstitutionID(institutionID),
			supportgrant.IsUsed(true),
			supportgrant.UsedByIDNotNil(),
			supportgrant.ExpiresAtGT(now),
		).
		Order(ent.Desc(supportgrant.FieldUsedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query active sessions: %w", err)
	}
	return grants, nil
}

// RevokeSessionByID marks a specific active support grant as expired (expires_at = now) scoped strictly to institutionID.
func (r *SupportGrantRepository) RevokeSessionByID(ctx context.Context, institutionID, grantID uuid.UUID) (*ent.SupportGrant, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	// First verify the grant exists and belongs to the specified institution
	grant, err := client.SupportGrant.Query().
		Where(
			supportgrant.ID(grantID),
			supportgrant.InstitutionID(institutionID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrGrantNotFound
		}
		return nil, fmt.Errorf("failed to query grant for revocation: %w", err)
	}

	// Expire the grant immediately
	now := time.Now()
	_, err = client.SupportGrant.UpdateOneID(grantID).
		Where(supportgrant.InstitutionID(institutionID)).
		SetExpiresAt(now).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to expire grant: %w", err)
	}

	grant.ExpiresAt = now
	return grant, nil
}
