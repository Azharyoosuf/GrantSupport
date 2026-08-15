package observability_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"grantsupport/pkg/observability"
)

func TestMetrics_PrometheusFormatCompliance(t *testing.T) {
	reg := observability.NewMetricRegistry()
	reg.IncGrantsCreated()
	reg.IncLogins("success")
	reg.IncLogins("failure")
	reg.IncAuthFailures("token_expired")
	reg.IncRevocations("tenant")
	reg.IncRateLimitExceeded("auth_login")
	reg.IncWebhookDispatches("delivered")
	reg.SetActiveSessions(5)
	reg.SetDBPoolStats(10, 2)
	reg.RecordHTTPRequest("auth_grant", 201, 15*time.Millisecond)

	handler := reg.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	body := rec.Body.String()

	// 1. Verify standard Prometheus headers
	if !strings.Contains(body, "# HELP grantsupport_grants_created_total") || !strings.Contains(body, "# TYPE grantsupport_grants_created_total counter") {
		t.Errorf("missing grants_created_total help or type declarations")
	}

	// 2. Verify metric values
	if !strings.Contains(body, "grantsupport_grants_created_total 1") {
		t.Errorf("expected grantsupport_grants_created_total 1, got body:\n%s", body)
	}
	if !strings.Contains(body, "grantsupport_active_sessions 5") {
		t.Errorf("expected grantsupport_active_sessions 5")
	}
	if !strings.Contains(body, "grantsupport_logins_total{status=\"success\"} 1") {
		t.Errorf("expected logins_total success 1")
	}
	if !strings.Contains(body, "grantsupport_http_requests_total{route=\"auth_grant\",status_code=\"201\"} 1") {
		t.Errorf("expected http_requests_total for auth_grant 201")
	}

	// 3. CRITICAL SECURITY ASSERTION: Verify ZERO PII or dynamic tenant/user UUIDs in metric output
	prohibitedSubstrings := []string{
		"uuid", "institution", "01a0", "550e8400", "@", "token_hash", "bearer", "password",
	}
	for _, sub := range prohibitedSubstrings {
		if strings.Contains(strings.ToLower(body), sub) {
			t.Fatalf("CRITICAL METRICS LEAKAGE: Prohibited substring '%s' found in metrics exposition output!", sub)
		}
	}
}
