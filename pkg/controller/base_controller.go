package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// AppError represents a structured application domain or validation error for RFC 7807 problem details.
type AppError struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (e *AppError) Error() string {
	return e.Detail
}

// NewAppError constructs a new AppError instance.
func NewAppError(status int, code, detail string) *AppError {
	return &AppError{
		Status: status,
		Code:   code,
		Detail: detail,
	}
}

// CatchAsync is the Go higher-order function equivalent of Node.js catchAsync middleware.
// It wraps controller handler methods, automatically enforcing RFC 7807 Problem Details formatting on errors.
func CatchAsync(fn func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			var appErr *AppError
			if errors.As(err, &appErr) {
				WriteRFC7807Error(w, appErr.Status, appErr.Code, appErr.Detail)
				return
			}

			// Validation Error mapping
			var validationErrs validator.ValidationErrors
			if errors.As(err, &validationErrs) {
				var sb strings.Builder
				for i, fieldErr := range validationErrs {
					if i > 0 {
						sb.WriteString("; ")
					}
					sb.WriteString(fmt.Sprintf("field '%s' failed validation rule '%s'", fieldErr.Field(), fieldErr.Tag()))
				}
				WriteRFC7807Error(w, http.StatusBadRequest, "VALIDATION_ERROR", sb.String())
				return
			}

			// Fallback runtime error (Sanitized to prevent internal database structure leakage)
			slog.Error("[UNHANDLED_HTTP_ERROR]", slog.String("error", err.Error()), slog.String("path", r.URL.Path))
			WriteRFC7807Error(w, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "An unexpected internal server error occurred. Please contact support.")
		}
	}
}

// DecodeAndValidate parses JSON payload into a target struct DTO and executes go-playground/validator v10 validation rules.
func DecodeAndValidate[T any](r *http.Request) (T, error) {
	var dto T
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		return dto, NewAppError(http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body format")
	}

	if err := validate.Struct(dto); err != nil {
		return dto, err
	}

	return dto, nil
}

// WriteJSON sends a standardized 200/201 JSON response.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// WriteRFC7807Error serializes an RFC 7807 Problem Details error response.
func WriteRFC7807Error(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":     "https://tenantpro.io/errors/" + strings.ToLower(code),
		"title":    code,
		"status":   status,
		"detail":   detail,
		"instance": "",
	})
}

// getRemoteIP extracts client remote IP safely prioritize Cloudflare headers without trusting raw X-Forwarded-For.
func getRemoteIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	return r.RemoteAddr
}
