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

// SupportGrant holds the schema definition for the SupportGrant entity.
type SupportGrant struct {
	ent.Schema
}

// Annotations of the SupportGrant.
func (SupportGrant) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "SupportGrant"},
	}
}

// Fields of the SupportGrant.
func (SupportGrant) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("granted_by_id", uuid.UUID{}),
		field.String("token_hash").Unique(),
		field.Time("expires_at"),
		field.Bool("is_used").Default(false),
		field.Time("used_at").Optional().Nillable(),
		field.String("scope").Default("FULL_ACCESS"),
		field.JSON("whitelisted_ips", []string{}).Optional(),
		field.Time("created_at").Default(time.Now),
	}
}

// Edges of the SupportGrant.
func (SupportGrant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("institution", Institution.Type).
			Ref("support_grants").
			Unique().
			Field("institution_id").
			Required(),
		edge.From("granted_by", User.Type).
			Ref("support_grants_created").
			Unique().
			Field("granted_by_id").
			Required(),
	}
}
