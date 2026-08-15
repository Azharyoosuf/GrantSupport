package scope

import (
	"strings"
)

// Matches checks whether the granted scope string satisfies the required scope.
// It is an optional standalone utility helper for host applications and does not
// alter GrantSupport's core JWT-carrying authorization semantics.
//
// Rules:
// 1. If required is empty (""), returns true.
// 2. If granted is empty ("") and required is non-empty, returns false.
// 3. If granted contains "*", it satisfies any required scope (global wildcard).
// 4. If granted contains "foo:*", it satisfies "foo:read", "foo:read:history", etc.
// 5. Non-terminal wildcards (e.g. "foo:*:bar" or "fo*o:bar") are strictly rejected (returns false).
// 6. Multiple scopes in granted can be separated by spaces or commas.
// 7. Matching is case-sensitive.
func Matches(grantedScope, requiredScope string) bool {
	req := strings.TrimSpace(requiredScope)
	if req == "" {
		return true
	}

	grantedList := ParseScopes(grantedScope)
	if len(grantedList) == 0 {
		return false
	}

	return Contains(grantedList, req)
}

// Contains checks if any scope in grantedScopes satisfies requiredScope.
func Contains(grantedScopes []string, requiredScope string) bool {
	req := strings.TrimSpace(requiredScope)
	if req == "" {
		return true
	}

	for _, g := range grantedScopes {
		if matchesSingle(g, req) {
			return true
		}
	}
	return false
}

// ParseScopes splits a comma- or space-separated scope string into individual trimmed tokens.
func ParseScopes(scopeStr string) []string {
	clean := strings.ReplaceAll(scopeStr, ",", " ")
	fields := strings.Fields(clean)
	res := make([]string, 0, len(fields))
	for _, f := range fields {
		trimmed := strings.TrimSpace(f)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

func matchesSingle(granted, required string) bool {
	granted = strings.TrimSpace(granted)
	required = strings.TrimSpace(required)

	if granted == "" || required == "" {
		return false
	}

	// 1. Global wildcard
	if granted == "*" {
		return true
	}

	// 2. Exact match
	if granted == required {
		return true
	}

	// 3. Reject forbidden non-terminal wildcards (e.g. "foo:*:bar", "fo*o:bar")
	if strings.Contains(granted, "*") && !strings.HasSuffix(granted, ":*") {
		return false
	}

	// 4. Terminal wildcard hierarchy match (e.g. "billing:*" matches "billing:read" or "billing:read:history")
	if strings.HasSuffix(granted, ":*") {
		prefix := strings.TrimSuffix(granted, "*") // "billing:"
		if strings.HasPrefix(required, prefix) {
			return true
		}
	}

	return false
}
