package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// AuditEvent holds the schema definition for the AuditEvent entity.
type AuditEvent struct {
	ent.Schema
}

// Annotations of the AuditEvent.
func (AuditEvent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "AuditEvent"},
	}
}

// Fields of the AuditEvent.
func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.UUID("institution_id", uuid.UUID{}),
		field.String("name"),
		field.Time("start_date"),
		field.Time("end_date"),
		field.String("description").Optional().Nillable(),
		field.Float("anomaly_multiplier").Default(1.0),
		field.UUID("created_by_id", uuid.UUID{}),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now),
	}
}

// Edges of the AuditEvent.
func (AuditEvent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("institution", Institution.Type).
			Ref("audit_events").
			Unique().
			Field("institution_id").
			Required(),
		edge.From("created_by", User.Type).
			Ref("events_created").
			Unique().
			Field("created_by_id").
			Required(),
	}
}
