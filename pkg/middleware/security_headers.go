// Package middleware provides security headers, HTTPS redirection, and trusted proxy inspection.
package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"grantsupport/pkg/config"
)

// SecurityHeadersMiddleware injects standard HTTP security headers appropriate for a production API.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Frame-Options", "DENY")

		// Emit HSTS header if connection is HTTPS (direct TLS or verified trusted proxy forwarded HTTPS)
		isHTTPS := r.TLS != nil
		if !isHTTPS && config.AppConfig != nil {
			trustedProxies := config.AppConfig.TrustedProxies
			socketHost := r.RemoteAddr
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				socketHost = host
			}
			socketHost = strings.TrimSpace(socketHost)
			if len(trustedProxies) > 0 && ValidateIPWhitelist(socketHost, trustedProxies) {
				if proto := strings.ToLower(r.Header.Get("X-Forwarded-Proto")); proto == "https" {
					isHTTPS = true
				}
			}
		}

		if isHTTPS && config.AppConfig != nil && config.AppConfig.HSTSEnabled {
			maxAge := config.AppConfig.HSTSMaxAge
			if maxAge <= 0 {
				maxAge = 31536000 // 1 year default
			}
			hstsValue := fmt.Sprintf("max-age=%d", maxAge)
			if config.AppConfig.HSTSIncludeSubdomains {
				hstsValue += "; includeSubDomains"
			}
			if config.AppConfig.HSTSPreload {
				hstsValue += "; preload"
			}
			w.Header().Set("Strict-Transport-Security", hstsValue)
		}

		next.ServeHTTP(w, r)
	})
}

// HTTPToHTTPSRedirectHandler constructs a redirect handler forwarding plaintext HTTP requests to HTTPS.
func HTTPToHTTPSRedirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
			host = host[:colonIdx]
		}

		targetURL := fmt.Sprintf("https://%s", host)
		if httpsPort != "" && httpsPort != "443" {
			targetURL = fmt.Sprintf("https://%s:%s", host, httpsPort)
		}
		targetURL += r.URL.RequestURI()

		http.Redirect(w, r, targetURL, http.StatusPermanentRedirect)
	})
}
