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

// AccessRequest holds the schema definition for the AccessRequest entity.
type AccessRequest struct {
	ent.Schema
}

// Annotations of the AccessRequest.
func (AccessRequest) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "gs_access_requests"},
	}
}

// Fields of the AccessRequest.
func (AccessRequest) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(func() uuid.UUID { return uuid.Must(uuid.NewV7()) }),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("requester_id", uuid.UUID{}),
		field.String("target_service").
			Optional().
			Nillable().
			MaxLen(128),
		field.String("reason").
			NotEmpty(),
		field.Int("requested_duration_minutes").
			Positive(),
		field.Int("approved_duration_minutes").
			Optional().
			Nillable(),
		field.String("requested_scope").
			Default("FULL_ACCESS"),
		field.String("approved_scope").
			Optional().
			Nillable(),
		field.JSON("requested_ips", []string{}).
			Optional().
			Default([]string{}),
		field.JSON("approved_ips", []string{}).
			Optional().
			Default([]string{}),
		field.String("status").
			Default("PENDING").
			MaxLen(32),
		field.Time("expires_at").
			SchemaType(map[string]string{
				dialect.MySQL:    "datetime(6)",
				dialect.Postgres: "timestamptz",
			}),
		field.UUID("approved_by_id", uuid.UUID{}).
			Optional().
			Nillable(),
		field.Time("approved_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{
				dialect.MySQL:    "datetime(6)",
				dialect.Postgres: "timestamptz",
			}),
		field.UUID("rejected_by_id", uuid.UUID{}).
			Optional().
			Nillable(),
		field.String("rejection_reason").
			Optional().
			Nillable(),
		field.Time("rejected_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{
				dialect.MySQL:    "datetime(6)",
				dialect.Postgres: "timestamptz",
			}),
		field.Time("cancelled_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{
				dialect.MySQL:    "datetime(6)",
				dialect.Postgres: "timestamptz",
			}),
		field.UUID("support_grant_id", uuid.UUID{}).
			Optional().
			Nillable(),
		field.Time("created_at").
			Default(time.Now).
			SchemaType(map[string]string{
				dialect.MySQL:    "datetime(6)",
				dialect.Postgres: "timestamptz",
			}),
	}
}

// Indexes of the AccessRequest.
func (AccessRequest) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("institution_id", "status"),
		index.Fields("institution_id", "requester_id"),
		index.Fields("expires_at"),
	}
}
