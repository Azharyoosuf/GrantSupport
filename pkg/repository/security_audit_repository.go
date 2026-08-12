package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
)

type SecurityAuditRepository struct {
	*BaseRepository
}

func NewSecurityAuditRepository(base *BaseRepository) *SecurityAuditRepository {
	return &SecurityAuditRepository{BaseRepository: base}
}

type AuditLogResult struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// AppendLog records a permanent append-only audit log entry in the database.
func (r *SecurityAuditRepository) AppendLog(ctx context.Context, institutionID, userID uuid.UUID, eventName, description string, tx *ent.Tx) (*AuditLogResult, error) {
	var builder *ent.AuditEventCreate
	if tx != nil {
		builder = tx.AuditEvent.Create()
	} else {
		client, err := r.GetClient(ctx)
		if err != nil {
			return nil, err
		}
		builder = client.AuditEvent.Create()
	}

	now := time.Now()
	event, err := builder.
		SetInstitutionID(institutionID).
		SetCreatedByID(userID).
		SetName(eventName).
		SetDescription(description).
		SetStartDate(now).
		SetEndDate(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return &AuditLogResult{
		ID:        event.ID,
		CreatedAt: event.CreatedAt,
	}, nil
}
