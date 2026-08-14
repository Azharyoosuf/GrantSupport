// Package apierrors implements standard Problem Details for HTTP APIs (RFC 9457, obsoleting RFC 7807).
package apierrors

import (
	"encoding/json"
	"net/http"
	"strings"
)

// InvalidParam represents specific field validation failures conforming to RFC 9457 extension members.
type InvalidParam struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// ProblemDetails represents the RFC 9457 Problem Details JSON format.
type ProblemDetails struct {
	Type          string         `json:"type"`
	Title         string         `json:"title"`
	Status        int            `json:"status"`
	Detail        string         `json:"detail"`
	Instance      string         `json:"instance,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	InvalidParams []InvalidParam `json:"invalid_params,omitempty"`
}

// Error implements the standard Go error interface.
func (pd *ProblemDetails) Error() string {
	return pd.Detail
}

// NewProblemDetails instantiates a custom RFC 9457 Problem Details error payload.
func NewProblemDetails(status int, errType, title, detail, instance, correlationID string, invalidParams ...InvalidParam) *ProblemDetails {
	if errType == "" {
		errType = "https://grantsupport.io/errors/" + strings.ToLower(title)
	}
	return &ProblemDetails{
		Type:          errType,
		Title:         title,
		Status:        status,
		Detail:        detail,
		Instance:      instance,
		CorrelationID: correlationID,
		InvalidParams: invalidParams,
	}
}

// WriteJSON sends the RFC 9457 compliant error format down the HTTP response writer.
func (pd *ProblemDetails) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(pd.Status)
	_ = json.NewEncoder(w).Encode(pd)
}

// WriteProblemDetails is a helper to write standard RFC 9457 responses directly with context extraction.
func WriteProblemDetails(w http.ResponseWriter, r *http.Request, status int, code, detail string, invalidParams ...InvalidParam) {
	instance := ""
	correlationID := ""
	if r != nil {
		instance = r.URL.Path
		correlationID = r.Header.Get("X-Correlation-ID")
	}

	pd := NewProblemDetails(status, "", code, detail, instance, correlationID, invalidParams...)
	pd.WriteJSON(w)
}

// WriteRFC7807 is an alias for WriteProblemDetails maintained for backward compatibility.
func WriteRFC7807(w http.ResponseWriter, r *http.Request, status int, code, detail string, invalidParams ...InvalidParam) {
	WriteProblemDetails(w, r, status, code, detail, invalidParams...)
}

// WriteRFC9457 is an explicit alias for WriteProblemDetails.
func WriteRFC9457(w http.ResponseWriter, r *http.Request, status int, code, detail string, invalidParams ...InvalidParam) {
	WriteProblemDetails(w, r, status, code, detail, invalidParams...)
}
