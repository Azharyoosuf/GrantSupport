package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
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
		entsql.Annotation{Table: "gs_support_grants"},
	}
}

// Fields of the SupportGrant.
func (SupportGrant) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(func() uuid.UUID { return uuid.Must(uuid.NewV7()) }),
		field.UUID("institution_id", uuid.UUID{}),
		field.UUID("granted_by_id", uuid.UUID{}),
		field.UUID("used_by_id", uuid.UUID{}).Optional().Nillable(),
		field.String("token_hash").Unique(),
		field.Time("expires_at"),
		field.Bool("is_used").Default(false),
		field.Time("used_at").Optional().Nillable(),
		// Scope is passed through to the issued JWT's claims but is NOT enforced by GrantSupport itself —
		// the host application consuming the JWT is responsible for checking this claim before permitting
		// any action. This is intentional; do not assume GrantSupport restricts behavior based on scope.
		field.String("scope").Default("FULL_ACCESS"),
		field.JSON("whitelisted_ips", []string{}).Optional().Default([]string{}),
		field.Time("created_at").Default(time.Now),
	}
}
