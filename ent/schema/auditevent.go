package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AuditEvent holds the schema definition for the AuditEvent entity.
type AuditEvent struct {
	ent.Schema
}

// Annotations of the AuditEvent.
func (AuditEvent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "gs_audit_events"},
	}
}

// Fields of the AuditEvent.
func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(func() uuid.UUID { return uuid.Must(uuid.NewV7()) }),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("actor_id", uuid.UUID{}),
		field.String("event_type"),
		field.String("description").Optional(),
		field.String("hash_chain").Optional(),
		field.String("signature").Optional(),
		field.Time("created_at").
			SchemaType(map[string]string{
				dialect.MySQL:    "datetime(6)",
				dialect.Postgres: "timestamptz",
			}).
			Default(time.Now),
	}
}

// Indexes of the AuditEvent.
func (AuditEvent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("institution_id", "created_at"),
		index.Fields("actor_id"),
		index.Fields("event_type"),
	}
}
