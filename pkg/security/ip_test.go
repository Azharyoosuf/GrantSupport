package security_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"grantsupport/pkg/security"
)

func TestValidateIPWhitelist(t *testing.T) {
	tests := []struct {
		name           string
		clientIP       string
		whitelistedIPs []string
		want           bool
	}{
		{
			name:           "Empty whitelist allows any IP",
			clientIP:       "203.0.113.10",
			whitelistedIPs: nil,
			want:           true,
		},
		{
			name:           "Empty slice whitelist allows any IP",
			clientIP:       "203.0.113.10",
			whitelistedIPs: []string{},
			want:           true,
		},
		{
			name:           "Exact IPv4 match allowed",
			clientIP:       "192.168.1.50",
			whitelistedIPs: []string{"192.168.1.50", "10.10.0.0/16"},
			want:           true,
		},
		{
			name:           "Exact IPv4 non-match rejected",
			clientIP:       "192.168.1.51",
			whitelistedIPs: []string{"192.168.1.50", "10.10.0.0/16"},
			want:           false,
		},
		{
			name:           "CIDR IPv4 match allowed",
			clientIP:       "10.10.255.254",
			whitelistedIPs: []string{"192.168.1.50", "10.10.0.0/16"},
			want:           true,
		},
		{
			name:           "CIDR IPv4 outside subnet rejected",
			clientIP:       "10.11.0.1",
			whitelistedIPs: []string{"192.168.1.50", "10.10.0.0/16"},
			want:           false,
		},
		{
			name:           "IPv6 exact match allowed",
			clientIP:       "2001:db8::1",
			whitelistedIPs: []string{"2001:db8::1"},
			want:           true,
		},
		{
			name:           "IPv6 CIDR match allowed",
			clientIP:       "2001:db8:abcd::42",
			whitelistedIPs: []string{"2001:db8::/32"},
			want:           true,
		},
		{
			name:           "IPv6 CIDR non-match rejected",
			clientIP:       "2001:db9::1",
			whitelistedIPs: []string{"2001:db8::/32"},
			want:           false,
		},
		{
			name:           "Invalid client IP rejected when whitelist is non-empty",
			clientIP:       "not-an-ip",
			whitelistedIPs: []string{"192.168.1.50"},
			want:           false,
		},
		{
			name:           "Empty client IP rejected when whitelist is non-empty",
			clientIP:       "",
			whitelistedIPs: []string{"192.168.1.50"},
			want:           false,
		},
		{
			name:           "Invalid entries and blank strings in whitelist are safely ignored",
			clientIP:       "10.0.0.5",
			whitelistedIPs: []string{"", "   ", "invalid-ip-entry", "999.999.999.999/99", "10.0.0.0/24"},
			want:           true,
		},
		{
			name:           "Whitelist with only invalid entries rejects valid client IP",
			clientIP:       "10.0.0.5",
			whitelistedIPs: []string{"", "invalid-cidr/33", "not-an-ip"},
			want:           false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := security.ValidateIPWhitelist(tc.clientIP, tc.whitelistedIPs)
			if got != tc.want {
				t.Fatalf("ValidateIPWhitelist(%q, %v) = %v, want %v", tc.clientIP, tc.whitelistedIPs, got, tc.want)
			}
		})
	}
}

func TestExtractClientIP(t *testing.T) {
	t.Run("Strips ephemeral port when no trusted proxies configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "203.0.113.15:54321"
		req.Header.Set("CF-Connecting-IP", "10.0.0.1")
		req.Header.Set("X-Real-IP", "10.0.0.2")
		req.Header.Set("X-Forwarded-For", "10.0.0.3")

		got := security.ExtractClientIP(req, nil)
		if got != "203.0.113.15" {
			t.Fatalf("Expected direct socket IP 203.0.113.15, got %q", got)
		}
	})

	t.Run("Untrusted proxy cannot spoof forwarding headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "198.51.100.77:44444"
		req.Header.Set("CF-Connecting-IP", "192.168.1.50")
		req.Header.Set("X-Real-IP", "192.168.1.51")
		req.Header.Set("X-Forwarded-For", "192.168.1.52, 10.0.0.1")

		got := security.ExtractClientIP(req, []string{"127.0.0.1", "10.0.0.0/8"})
		if got != "198.51.100.77" {
			t.Fatalf("Expected untrusted peer socket IP 198.51.100.77, got %q", got)
		}
	})

	t.Run("Header precedence: CF-Connecting-IP over X-Real-IP and X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:8080"
		req.Header.Set("CF-Connecting-IP", "203.0.113.101")
		req.Header.Set("X-Real-IP", "203.0.113.102")
		req.Header.Set("X-Forwarded-For", "203.0.113.103, 10.0.0.1")

		got := security.ExtractClientIP(req, []string{"10.0.0.0/8"})
		if got != "203.0.113.101" {
			t.Fatalf("Expected CF-Connecting-IP 203.0.113.101 to take highest precedence, got %q", got)
		}
	})

	t.Run("Header precedence: X-Real-IP over X-Forwarded-For when CF-Connecting-IP absent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:8080"
		req.Header.Set("X-Real-IP", "203.0.113.102")
		req.Header.Set("X-Forwarded-For", "203.0.113.103, 10.0.0.1")

		got := security.ExtractClientIP(req, []string{"10.0.0.0/8"})
		if got != "203.0.113.102" {
			t.Fatalf("Expected X-Real-IP 203.0.113.102 to take precedence over X-Forwarded-For, got %q", got)
		}
	})

	t.Run("Header precedence: X-Forwarded-For leftmost IP used when CF-Connecting-IP and X-Real-IP absent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:8080"
		req.Header.Set("X-Forwarded-For", "203.0.113.103, 172.16.0.5, 10.0.0.1")

		got := security.ExtractClientIP(req, []string{"10.0.0.0/8"})
		if got != "203.0.113.103" {
			t.Fatalf("Expected leftmost X-Forwarded-For IP 203.0.113.103, got %q", got)
		}
	})

	t.Run("Invalid header values fall through to valid header or socket IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "127.0.0.1:8080"
		req.Header.Set("CF-Connecting-IP", "malformed-ip")
		req.Header.Set("X-Real-IP", "also-bad")
		req.Header.Set("X-Forwarded-For", "2001:db8::42, 127.0.0.1")

		got := security.ExtractClientIP(req, []string{"127.0.0.1"})
		if got != "2001:db8::42" {
			t.Fatalf("Expected fallback to valid IPv6 in X-Forwarded-For 2001:db8::42, got %q", got)
		}
	})
}
