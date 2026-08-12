package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"

	"grantsupport/ent/schema/types"
)

// ApiUsageLog holds the schema definition for the ApiUsageLog entity.
type ApiUsageLog struct {
	ent.Schema
}

// Annotations of the ApiUsageLog.
func (ApiUsageLog) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "ApiUsageLog"},
	}
}

// Fields of the ApiUsageLog.
func (ApiUsageLog) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.UUID("institution_id", uuid.UUID{}),
		field.String("provider"),
		field.String("action"),
		field.Other("wholesale_cost", types.Decimal{}).SchemaType(map[string]string{dialect.Postgres: "NUMERIC(20, 4)"}),
		field.Other("retail_price", types.Decimal{}).SchemaType(map[string]string{dialect.Postgres: "NUMERIC(20, 4)"}),
		field.JSON("metadata", map[string]any{}).Optional(),
		field.Time("created_at").Default(time.Now),
	}
}

// Edges of the ApiUsageLog.
func (ApiUsageLog) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("institution", Institution.Type).
			Ref("api_usage_logs").
			Unique().
			Field("institution_id").
			Required(),
	}
}
