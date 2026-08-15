package scope_test

import (
	"testing"

	"grantsupport/pkg/scope"
)

func TestScope_DeterministicMatching(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required string
		expected bool
	}{
		{"Empty required scope always passes", "billing:read", "", true},
		{"Empty granted scope fails non-empty required", "", "billing:read", false},
		{"Both empty scopes pass", "", "", true},
		{"Exact match passes", "billing:read", "billing:read", true},
		{"Exact mismatch fails", "billing:read", "billing:write", false},
		{"Global wildcard satisfies any requirement", "*", "billing:read:deep", true},
		{"Global wildcard satisfies global requirement", "*", "*", true},
		{"Terminal wildcard matches child read", "billing:*", "billing:read", true},
		{"Terminal wildcard matches child write", "billing:*", "billing:write", true},
		{"Terminal wildcard matches deep hierarchy subtree", "billing:*", "billing:read:history:export", true},
		{"Terminal wildcard does not match unrelated prefix", "billing:*", "billing_v2:read", false},
		{"Narrower granted does not satisfy wildcard required", "billing:read", "billing:*", false},
		{"Exact prefix does not match deep hierarchy without wildcard", "billing:read", "billing:read:history", false},
		{"Non-terminal wildcard is forbidden and fails", "billing:*:read", "billing:v1:read", false},
		{"Embedded wildcard is forbidden and fails", "bil*ing:read", "billing:read", false},
		{"Multiple scopes space-separated matches first", "billing:read org:admin", "billing:read", true},
		{"Multiple scopes space-separated matches second", "billing:read org:admin", "org:admin", true},
		{"Multiple scopes comma-separated matches", "billing:read,org:admin", "org:admin", true},
		{"Multiple scopes comma-space-separated matches wildcard", "billing:*, org:admin", "billing:custom:action", true},
		{"Case-sensitive matching fails on case mismatch", "Billing:Read", "billing:read", false},
		{"Whitespace around tokens is handled cleanly", "  billing:read ,  org:admin  ", "billing:read", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scope.Matches(tt.granted, tt.required)
			if got != tt.expected {
				t.Errorf("Matches(%q, %q) = %v, expected %v", tt.granted, tt.required, got, tt.expected)
			}
		})
	}
}

func TestScope_ParseScopes(t *testing.T) {
	tokens := scope.ParseScopes("billing:read, org:admin   user:write  ,audit:*")
	expected := []string{"billing:read", "org:admin", "user:write", "audit:*"}

	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expected), len(tokens), tokens)
	}

	for i, exp := range expected {
		if tokens[i] != exp {
			t.Errorf("token %d: expected %s, got %s", i, exp, tokens[i])
		}
	}
}
