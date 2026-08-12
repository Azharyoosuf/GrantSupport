package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"grantsupport/ent"
	"grantsupport/ent/apiusagelog"
	"grantsupport/ent/schema/types"
)

type ApiUsageLogRepository struct {
	*BaseRepository
}

func NewApiUsageLogRepository(base *BaseRepository) *ApiUsageLogRepository {
	return &ApiUsageLogRepository{BaseRepository: base}
}

type RecordUsageInput struct {
	InstitutionID uuid.UUID      `json:"institution_id"`
	Provider      string         `json:"provider"`
	Action        string         `json:"action"`
	WholesaleCost float64        `json:"wholesale_cost"`
	RetailPrice   float64        `json:"retail_price"`
	Metadata      map[string]any `json:"metadata"`
}

// RecordUsage appends a new API usage log entry (append-only).
func (r *ApiUsageLogRepository) RecordUsage(ctx context.Context, input RecordUsageInput, tx *ent.Tx) (*ent.ApiUsageLog, error) {
	var builder *ent.ApiUsageLogCreate
	if tx != nil {
		builder = tx.ApiUsageLog.Create()
	} else {
		client, err := r.GetClient(ctx)
		if err != nil {
			return nil, err
		}
		builder = client.ApiUsageLog.Create()
	}

	return builder.
		SetInstitutionID(input.InstitutionID).
		SetProvider(input.Provider).
		SetAction(input.Action).
		SetWholesaleCost(types.Decimal{Decimal: decimal.NewFromFloat(input.WholesaleCost)}).
		SetRetailPrice(types.Decimal{Decimal: decimal.NewFromFloat(input.RetailPrice)}).
		SetMetadata(input.Metadata).
		Save(ctx)
}

type ApiProviderSummary struct {
	Provider       string  `json:"provider"`
	TotalWholesale float64 `json:"total_wholesale"`
	TotalRetail    float64 `json:"total_retail"`
	Count          int     `json:"count"`
}

// GetUsageSummary aggregates API usage grouped by provider for a given month/year.
func (r *ApiUsageLogRepository) GetUsageSummary(ctx context.Context, institutionID uuid.UUID, month, year int) ([]ApiProviderSummary, error) {
	startDate := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	endDate := startDate.AddDate(0, 1, 0)

	if r.PgxPool == nil {
		client, err := r.GetClient(ctx)
		if err != nil {
			return nil, err
		}
		var v []struct {
			Provider  string  `json:"provider"`
			Wholesale float64 `json:"sum_wholesale_cost"`
			Retail    float64 `json:"sum_retail_price"`
			Count     int     `json:"count"`
		}
		err = client.ApiUsageLog.Query().
			Where(
				apiusagelog.InstitutionID(institutionID),
				apiusagelog.CreatedAtGTE(startDate),
				apiusagelog.CreatedAtLT(endDate),
			).
			GroupBy(apiusagelog.FieldProvider).
			Aggregate(
				ent.As(ent.Sum(apiusagelog.FieldWholesaleCost), "sum_wholesale_cost"),
				ent.As(ent.Sum(apiusagelog.FieldRetailPrice), "sum_retail_price"),
				ent.As(ent.Count(), "count"),
			).
			Scan(ctx, &v)
		if err != nil {
			return nil, err
		}

		summaries := make([]ApiProviderSummary, len(v))
		for i, val := range v {
			summaries[i] = ApiProviderSummary{
				Provider:       val.Provider,
				TotalWholesale: val.Wholesale,
				TotalRetail:    val.Retail,
				Count:          val.Count,
			}
		}
		return summaries, nil
	}

	query := `
		SELECT provider, COALESCE(SUM(wholesale_cost), 0), COALESCE(SUM(retail_price), 0), COUNT(*)
		FROM "ApiUsageLog"
		WHERE institution_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY provider
	`

	rows, err := r.PgxPool.Query(ctx, query, institutionID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var summaries []ApiProviderSummary
	for rows.Next() {
		var s ApiProviderSummary
		if err := rows.Scan(&s.Provider, &s.TotalWholesale, &s.TotalRetail, &s.Count); err != nil {
			return nil, err
		}
		summaries = append(summaries, s)
	}

	return summaries, nil
}

// GetUsageByProvider retrieves paginated detailed usage logs for a specific provider, institution, and month.
func (r *ApiUsageLogRepository) GetUsageByProvider(ctx context.Context, institutionID uuid.UUID, provider string, month, year, skip, take int) ([]*ent.ApiUsageLog, error) {
	startDate := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	endDate := startDate.AddDate(0, 1, 0)

	safeTake := take
	if safeTake > 100 {
		safeTake = 100
	} else if safeTake <= 0 {
		safeTake = 50
	}

	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}

	return client.ApiUsageLog.Query().
		Where(
			apiusagelog.InstitutionID(institutionID),
			apiusagelog.Provider(provider),
			apiusagelog.CreatedAtGTE(startDate),
			apiusagelog.CreatedAtLT(endDate),
		).
		Offset(skip).
		Limit(safeTake).
		Order(ent.Desc(apiusagelog.FieldCreatedAt)).
		Select(
			apiusagelog.FieldID,
			apiusagelog.FieldInstitutionID,
			apiusagelog.FieldProvider,
			apiusagelog.FieldAction,
			apiusagelog.FieldWholesaleCost,
			apiusagelog.FieldRetailPrice,
			apiusagelog.FieldMetadata,
			apiusagelog.FieldCreatedAt,
		).
		All(ctx)
}

// GetUsageLogs retrieves paginated API usage log entries for an institution.
func (r *ApiUsageLogRepository) GetUsageLogs(ctx context.Context, institutionID uuid.UUID, skip, take int) ([]*ent.ApiUsageLog, error) {
	client, err := r.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	if take <= 0 {
		take = 20
	} else if take > 100 {
		take = 100
	}
	return client.ApiUsageLog.Query().
		Where(apiusagelog.InstitutionID(institutionID)).
		Offset(skip).
		Limit(take).
		Order(ent.Desc(apiusagelog.FieldCreatedAt)).
		All(ctx)
}
