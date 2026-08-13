package security

import (
	"regexp"
	"strings"
)

var (
	// Email regex matching standard RFC 5322 email patterns
	emailRegex = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)

	// Credit Card / PAN regex (13 to 19 digits with optional hyphens or spaces)
	creditCardRegex = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)

	// Bearer tokens, passwords (quoted or unquoted), and secrets
	secretRegex = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*|password\s*=\s*"[^"]*"|password\s*=\s*'[^']*'|password["'\s:=]+[^\s,"']+|secret\s*=\s*"[^"]*"|secret\s*=\s*'[^']*'|secret["'\s:=]+[^\s,"']+)`)

	// Phone numbers (e.g. +1-800-555-0199, +1 (555) 234-5678, (555) 234-5678, 123-456-7890)
	phoneRegex = regexp.MustCompile(`(?i)(?:\+\d{1,3}[-.\s]*\(?\d{3}\)?|\b\(?\d{3}\)?)[-.\s]*\d{3}[-.\s]*\d{4}\b`)
)

// SanitizeAuditText cleans and redacts sensitive credentials and PII from audit strings.
func SanitizeAuditText(text string) string {
	if text == "" {
		return ""
	}

	sanitized := text

	// 1. Redact Secrets & Bearer Tokens
	sanitized = secretRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
		parts := strings.SplitN(match, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return "Bearer [REDACTED_TOKEN]"
		}
		return "[REDACTED_SECRET]"
	})

	// 2. Redact Emails
	sanitized = emailRegex.ReplaceAllString(sanitized, "[REDACTED_EMAIL]")

	// 3. Redact Credit Card numbers (ensure length >= 13 pure digits)
	sanitized = creditCardRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
		digitsOnly := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, match)
		if len(digitsOnly) >= 13 && len(digitsOnly) <= 19 {
			return "[REDACTED_CARD]"
		}
		return match
	})

	// 4. Redact Phone numbers (exclude UUID hexadecimal strings)
	sanitized = phoneRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
		digitsOnly := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, match)
		if len(digitsOnly) >= 10 && len(digitsOnly) <= 15 {
			return "[REDACTED_PHONE]"
		}
		return match
	})

	return sanitized
}

// SanitizeAuditMap recursively sanitizes all string values within an audit event details map.
func SanitizeAuditMap(data map[string]any) map[string]any {
	if data == nil {
		return nil
	}

	sanitized := make(map[string]any, len(data))
	for k, v := range data {
		lowerKey := strings.ToLower(k)
		if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "secret") || strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "key") {
			sanitized[k] = "[REDACTED_SECRET]"
			continue
		}

		switch val := v.(type) {
		case string:
			sanitized[k] = SanitizeAuditText(val)
		case map[string]any:
			sanitized[k] = SanitizeAuditMap(val)
		default:
			sanitized[k] = v
		}
	}

	return sanitized
}
