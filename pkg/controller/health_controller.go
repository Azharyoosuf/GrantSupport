package controller

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// HealthController handles process liveness and dependency readiness probes.
type HealthController struct {
	version     string
	sqlDB       *sql.DB
	redisClient *redis.Client
}

// NewHealthController constructs a HealthController instance.
func NewHealthController(version string, sqlDB *sql.DB, redisClient *redis.Client) *HealthController {
	return &HealthController{
		version:     version,
		sqlDB:       sqlDB,
		redisClient: redisClient,
	}
}

// Live handles the fast process liveness probe.
// GET /health/live
func (c *HealthController) Live(w http.ResponseWriter, r *http.Request) error {
	WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "UP",
		"service": "GrantSupport Engine",
		"version": c.version,
	})
	return nil
}

// Ready handles the deep dependency readiness probe.
// Mandatory: Primary SQL Database.
// Optional: Valkey/Redis (checked only if configured; SQL-only mode remains healthy without Valkey).
// GET /health/ready
func (c *HealthController) Ready(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// 1. Mandatory SQL DB Check
	if c.sqlDB != nil {
		if err := c.sqlDB.PingContext(ctx); err != nil {
			return NewAppError(http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE", "Primary SQL database connection ping failed: "+err.Error())
		}
	}

	// 2. Optional Valkey Check
	valkeyStatus := "NOT_CONFIGURED"
	deploymentMode := "sql-only"
	if c.redisClient != nil {
		deploymentMode = "valkey-enabled"
		if err := c.redisClient.Ping(ctx).Err(); err != nil {
			return NewAppError(http.StatusServiceUnavailable, "VALKEY_UNAVAILABLE", "Configured Valkey/Redis connection ping failed: "+err.Error())
		}
		valkeyStatus = "UP"
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"status":   "READY",
		"database": "UP",
		"valkey":   valkeyStatus,
		"mode":     deploymentMode,
		"version":  c.version,
	})
	return nil
}
