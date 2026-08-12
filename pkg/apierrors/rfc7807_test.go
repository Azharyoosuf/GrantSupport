package apierrors_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"grantsupport/pkg/apierrors"
)

func TestWriteRFC7807(t *testing.T) {
	t.Run("Serializes ProblemDetails with invalid_params and correlation_id", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/test", nil)
		req.Header.Set("X-Correlation-ID", "corr_12345")
		rr := httptest.NewRecorder()

		invalidParams := []apierrors.InvalidParam{
			{Name: "duration_minutes", Reason: "must be positive"},
		}

		apierrors.WriteRFC7807(rr, req, http.StatusBadRequest, "INVALID_INPUT", "Validation failed", invalidParams...)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}

		if contentType := rr.Header().Get("Content-Type"); contentType != "application/problem+json" {
			t.Errorf("Expected Content-Type application/problem+json, got %s", contentType)
		}

		var pd apierrors.ProblemDetails
		if err := json.Unmarshal(rr.Body.Bytes(), &pd); err != nil {
			t.Fatalf("Failed to unmarshal ProblemDetails response: %v", err)
		}

		if pd.Title != "INVALID_INPUT" {
			t.Errorf("Expected title INVALID_INPUT, got %s", pd.Title)
		}
		if pd.Instance != "/api/v1/test" {
			t.Errorf("Expected instance /api/v1/test, got %s", pd.Instance)
		}
		if pd.CorrelationID != "corr_12345" {
			t.Errorf("Expected correlation_id corr_12345, got %s", pd.CorrelationID)
		}
		if len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Name != "duration_minutes" {
			t.Errorf("Expected invalid_params for duration_minutes, got %+v", pd.InvalidParams)
		}
	})
}
