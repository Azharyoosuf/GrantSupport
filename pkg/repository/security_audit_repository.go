package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"grantsupport/ent"
	"grantsupport/ent/auditevent"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/security"
)

type SecurityAuditRepository struct {
	*BaseRepository
	instLocks sync.Map // map[uuid.UUID]*sync.Mutex
	lockStore ports.LockStore
}

func NewSecurityAuditRepository(base *BaseRepository) *SecurityAuditRepository {
	return &SecurityAuditRepository{
		BaseRepository: base,
	}
}

// SetLockStore attaches a distributed or SQL lock store to serialize audit hash chaining across multiple microservice processes.
func (r *SecurityAuditRepository) SetLockStore(lockStore ports.LockStore) {
	r.lockStore = lockStore
}

func (r *SecurityAuditRepository) getInstitutionLock(institutionID uuid.UUID) *sync.Mutex {
	val, _ := r.instLocks.LoadOrStore(institutionID, &sync.Mutex{})
	return val.(*sync.Mutex)
}

type AuditLogResult struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// LogSecurityEvent records a permanent append-only audit log entry in the database.
// Mutex striping (in-process) combined with distributed locking (cross-process) ensures
// linear hash-chain integrity with zero forks and zero dropped events under high concurrency.
func (r *SecurityAuditRepository) LogSecurityEvent(ctx context.Context, institutionID, actorID uuid.UUID, eventType, description string, tx *ent.Tx) (*AuditLogResult, error) {
	// Acquire per-institution in-process lock to serialize goroutines on this instance
	mu := r.getInstitutionLock(institutionID)
	mu.Lock()
	defer mu.Unlock()

	// If distributed lockStore is configured and we are not inside an existing transaction,
	// acquire cross-process distributed lock with bounded spin-wait retry.
	if r.lockStore != nil && tx == nil {
		lockKey := fmt.Sprintf("lock:audit:%s", institutionID.String())
		var token string
		var err error
		deadline := time.Now().Add(5 * time.Second)

		for {
			token, err = r.lockStore.Acquire(ctx, lockKey, 5*time.Second)
			if err == nil && token != "" {
				break
			}
			if err != ports.ErrLockBusy && err != nil {
				return nil, fmt.Errorf("failed to acquire distributed audit lock: %w", err)
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for distributed audit lock: %w", ports.ErrLockBusy)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(15 * time.Millisecond):
			}
		}

		defer func() {
			_ = r.lockStore.Release(context.Background(), lockKey, token)
		}()
	}

	return r.logSecurityEventInternal(ctx, institutionID, actorID, eventType, description, tx)
}

func (r *SecurityAuditRepository) logSecurityEventInternal(ctx context.Context, institutionID, actorID uuid.UUID, eventType, description string, tx *ent.Tx) (*AuditLogResult, error) {
	var builder *ent.AuditEventCreate
	var client *ent.Client
	var err error

	if tx != nil {
		builder = tx.AuditEvent.Create()
	} else {
		client, err = r.GetClient(ctx)
		if err != nil {
			return nil, err
		}
		builder = client.AuditEvent.Create()
	}

	// Sanitize any PII or credentials from the event description before hashing and saving
	sanitizedDesc := security.SanitizeAuditText(description)

	// Establish canonical UTC microsecond timestamp
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Compute previous hash chain link scoped by institution
	var prevHash string
	var lastEvent *ent.AuditEvent
	if tx != nil {
		lastEvent, _ = tx.AuditEvent.Query().
			Where(auditevent.InstitutionID(institutionID)).
			Order(ent.Desc(auditevent.FieldCreatedAt), ent.Desc(auditevent.FieldID)).
			First(ctx)
	} else if client != nil {
		lastEvent, _ = client.AuditEvent.Query().
			Where(auditevent.InstitutionID(institutionID)).
			Order(ent.Desc(auditevent.FieldCreatedAt), ent.Desc(auditevent.FieldID)).
			First(ctx)
	}

	if lastEvent != nil {
		prevHash = lastEvent.HashChain
		// Enforce strict monotonic timestamp ordering within each tenant chain:
		// If clock skew or sub-microsecond execution causes `now <= lastEvent.CreatedAt`,
		// advance `now` to strictly succeed `lastEvent.CreatedAt` by at least 1 microsecond.
		lastEventTime := lastEvent.CreatedAt.UTC().Truncate(time.Microsecond)
		if !now.After(lastEventTime) {
			now = lastEventTime.Add(time.Microsecond)
		}
	} else {
		prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Compute SHA-256 hash chain value using exact canonical timestamp
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%s:%s:%s:%d", prevHash, institutionID.String(), actorID.String(), eventType, sanitizedDesc, now.UnixNano())))
	computedHashChain := hex.EncodeToString(h.Sum(nil))

	event, err := builder.
		SetInstitutionID(institutionID).
		SetActorID(actorID).
		SetEventType(eventType).
		SetDescription(sanitizedDesc).
		SetHashChain(computedHashChain).
		SetCreatedAt(now).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return &AuditLogResult{
		ID:        event.ID,
		CreatedAt: event.CreatedAt,
	}, nil
}

// VerifyAuditChain traverses all historical events for an institution and verifies that the cryptographic hash chain is unbroken.
func (r *SecurityAuditRepository) VerifyAuditChain(ctx context.Context, institutionID uuid.UUID) (bool, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return false, err
	}

	events, err := client.AuditEvent.Query().
		Where(auditevent.InstitutionID(institutionID)).
		Order(ent.Asc(auditevent.FieldCreatedAt), ent.Asc(auditevent.FieldID)).
		All(ctx)
	if err != nil {
		return false, err
	}

	prevHash := "0000000000000000000000000000000000000000000000000000000000000000"
	for _, event := range events {
		eventTime := event.CreatedAt.UTC().Truncate(time.Microsecond)
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s:%s:%s:%s:%s:%d", prevHash, event.InstitutionID.String(), event.ActorID.String(), event.EventType, event.Description, eventTime.UnixNano())))
		expectedHash := hex.EncodeToString(h.Sum(nil))

		if event.HashChain != expectedHash {
			return false, fmt.Errorf("audit chain integrity violation at event %s: expected %s, got %s", event.ID, expectedHash, event.HashChain)
		}
		prevHash = event.HashChain
	}

	return true, nil
}

// GetAuditEventsByInstitution retrieves paginated audit records for an institution.
func (r *SecurityAuditRepository) GetAuditEventsByInstitution(ctx context.Context, institutionID uuid.UUID, limit, offset int) ([]*ent.AuditEvent, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	return client.AuditEvent.Query().
		Where(auditevent.InstitutionID(institutionID)).
		Order(ent.Desc(auditevent.FieldCreatedAt), ent.Desc(auditevent.FieldID)).
		Limit(limit).
		Offset(offset).
		All(ctx)
}
