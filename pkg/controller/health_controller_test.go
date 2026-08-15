package controller_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"grantsupport/pkg/controller"
	_ "modernc.org/sqlite"
)

func TestHealthController_LivenessProbe(t *testing.T) {
	healthCtrl := controller.NewHealthController("v0.1.0-beta.2", nil, nil)
	handler := controller.CatchAsync(healthCtrl.Live)

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var resp struct {
		Status  string `json:"status"`
		Service string `json:"service"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Status != "UP" || resp.Service != "GrantSupport Engine" {
		t.Errorf("unexpected live response: %+v", resp)
	}
}

func TestHealthController_ReadinessInSQLOnlyMode(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	defer db.Close()

	healthCtrl := controller.NewHealthController("v0.1.0-beta.2", db, nil)
	handler := controller.CatchAsync(healthCtrl.Ready)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 in SQL-only mode, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Status   string `json:"status"`
		Database string `json:"database"`
		Valkey   string `json:"valkey"`
		Mode     string `json:"mode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode readiness response: %v", err)
	}

	if resp.Status != "READY" || resp.Database != "UP" || resp.Valkey != "NOT_CONFIGURED" || resp.Mode != "sql-only" {
		t.Errorf("unexpected readiness payload: %+v", resp)
	}
}

func TestHealthController_ReadinessFailsWhenDBDown(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	// Intentionally close database to simulate outage
	_ = db.Close()

	healthCtrl := controller.NewHealthController("v0.1.0-beta.2", db, nil)
	handler := controller.CatchAsync(healthCtrl.Ready)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected HTTP 503 when DB is down, got %d: %s", rec.Code, rec.Body.String())
	}
}
