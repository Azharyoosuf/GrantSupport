package security_test

import (
	"strings"
	"testing"

	"grantsupport/pkg/security"
)

func TestSanitizeAuditText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Redacts email address",
			input:    "User admin@company.com accessed support console",
			expected: "User [REDACTED_EMAIL] accessed support console",
		},
		{
			name:     "Redacts credit card number",
			input:    "Payment attempt with 4111-2222-3333-4444 failed",
			expected: "Payment attempt with [REDACTED_CARD] failed",
		},
		{
			name:     "Redacts phone number",
			input:    "Called support phone +1-800-555-0199 for escalation",
			expected: "Called support phone [REDACTED_PHONE] for escalation",
		},
		{
			name:     "Redacts bearer token",
			input:    "API call with Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc12345",
			expected: "API call with Bearer [REDACTED_TOKEN]",
		},
		{
			name:     "Redacts password string",
			input:    "Configured password=\"superSecret123!\" in payload",
			expected: "Configured [REDACTED_SECRET] in payload",
		},
		{
			name:     "Empty text remains empty",
			input:    "",
			expected: "",
		},
		{
			name:     "Harmless text remains unaltered",
			input:    "Support session started by agent 550e8400-e29b-41d4-a716-446655440000",
			expected: "Support session started by agent 550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := security.SanitizeAuditText(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeAuditText(%q) = %q; expected %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSanitizeAuditMap(t *testing.T) {
	input := map[string]any{
		"admin_email": "john.doe@example.org",
		"password":    "secretP@ssw0rd",
		"nested": map[string]any{
			"phone": "+1 (555) 234-5678",
		},
		"count": 42,
	}

	sanitized := security.SanitizeAuditMap(input)

	if sanitized["admin_email"] != "[REDACTED_EMAIL]" {
		t.Errorf("Expected email to be redacted, got %v", sanitized["admin_email"])
	}
	if sanitized["password"] != "[REDACTED_SECRET]" {
		t.Errorf("Expected password to be redacted, got %v", sanitized["password"])
	}
	nested := sanitized["nested"].(map[string]any)
	if !strings.Contains(nested["phone"].(string), "REDACTED_PHONE") {
		t.Errorf("Expected nested phone to be redacted, got %v", nested["phone"])
	}
	if sanitized["count"] != 42 {
		t.Errorf("Expected primitive non-string values to be preserved, got %v", sanitized["count"])
	}
}
