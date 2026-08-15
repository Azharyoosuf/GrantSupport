// Package security provides cryptographic, token, transport, and client IP validation utilities.
package security

import (
	"net"
	"net/http"
	"strings"
)

// ExtractClientIP extracts the client IP address from a request, stripping ephemeral TCP ports
// and verifying proxy headers against trusted proxy ranges to prevent IP spoofing.
func ExtractClientIP(r *http.Request, trustedProxies []string) string {
	socketHost := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		socketHost = host
	}
	socketHost = strings.TrimSpace(socketHost)

	// If no trusted proxies are configured, or if the direct socket connection is NOT from a trusted proxy,
	// return the direct socket TCP host to prevent header spoofing.
	if len(trustedProxies) == 0 || !ValidateIPWhitelist(socketHost, trustedProxies) {
		return socketHost
	}

	// Direct socket connection is from a trusted reverse proxy (e.g. Cloudflare / AWS ALB):
	// Inspect proxy headers in order of priority.
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		if net.ParseIP(cfIP) != nil {
			return cfIP
		}
	}

	if xRealIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); xRealIP != "" {
		if net.ParseIP(xRealIP) != nil {
			return xRealIP
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			firstIP := strings.TrimSpace(parts[0])
			if net.ParseIP(firstIP) != nil {
				return firstIP
			}
		}
	}

	return socketHost
}

// ValidateIPWhitelist verifies if a client IP matches a list of whitelisted IPs or CIDR subnets.
// If whitelistedIPs is empty, it returns true (no IP restrictions configured).
func ValidateIPWhitelist(clientIP string, whitelistedIPs []string) bool {
	if len(whitelistedIPs) == 0 {
		return true
	}

	clientIP = strings.TrimSpace(clientIP)
	parsedClientIP := net.ParseIP(clientIP)
	if parsedClientIP == nil {
		return false
	}

	for _, entry := range whitelistedIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Exact IP match
		if entry == clientIP {
			return true
		}

		// CIDR subnet match (e.g. 192.168.1.0/24 or 10.0.0.0/8)
		if strings.Contains(entry, "/") {
			_, subnet, err := net.ParseCIDR(entry)
			if err == nil && subnet.Contains(parsedClientIP) {
				return true
			}
		}
	}

	return false
}
