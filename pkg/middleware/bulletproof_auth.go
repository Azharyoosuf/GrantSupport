// Package middleware provides HTTP middlewares for authentication, rate limiting, and 5-layer bulletproof security.
package middleware

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"grantsupport/pkg/config"
	pkgctx "grantsupport/pkg/context"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/ports"
	"grantsupport/pkg/security"
)

type contextKey string

const (
	BulletproofContextKey contextKey = "bulletproof_security_context"
)

// BulletproofSecurityContext holds authenticated metadata injected into r.Context().
type BulletproofSecurityContext struct {
	KeyID         string
	InstitutionID string
	ClientIP      string
	ExpiresAt     int64
	PublicKey     ed25519.PublicKey
}

// GetBulletproofSecurityContext retrieves BulletproofSecurityContext from request context.
func GetBulletproofSecurityContext(ctx context.Context) (*BulletproofSecurityContext, bool) {
	bctx, ok := ctx.Value(BulletproofContextKey).(*BulletproofSecurityContext)
	return bctx, ok
}

// GetRealClientIP extracts real client IP directly from socket or trusted proxy headers.
func GetRealClientIP(r *http.Request) string {
	var trustedProxies []string
	if config.AppConfig != nil {
		trustedProxies = config.AppConfig.TrustedProxies
	}
	return ExtractClientIP(r, trustedProxies)
}

// ValidateIPWhitelist verifies if a client IP matches a list of whitelisted IPs or CIDR subnets.
func ValidateIPWhitelist(clientIP string, whitelistedIPs []string) bool {
	if len(whitelistedIPs) == 0 {
		return true // No restriction
	}

	parsedClientIP := net.ParseIP(clientIP)
	if parsedClientIP == nil {
		return false
	}

	for _, entry := range whitelistedIPs {
		entry = strings.TrimSpace(entry)
		// Check exact match
		if entry == clientIP {
			return true
		}
		// Check CIDR range match (e.g. 192.168.1.0/24)
		if strings.Contains(entry, "/") {
			_, subnet, err := net.ParseCIDR(entry)
			if err == nil && subnet.Contains(parsedClientIP) {
				return true
			}
		}
	}

	return false
}

// BulletproofAuthMiddleware returns a 5-Layer Security HTTP middleware handler.
func BulletproofAuthMiddleware(replayStore ports.ReplayStore, keyStore map[string]*security.APIKeyDetails) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Security Headers
			keyID := r.Header.Get("X-API-KEY-ID")
			signatureB64 := r.Header.Get("X-SIGNATURE")
			nonce := r.Header.Get("X-NONCE")
			expiresAtStr := r.Header.Get("X-EXPIRES-AT")

			// Require headers for 5-Layer Security requests
			if keyID == "" || signatureB64 == "" || nonce == "" || expiresAtStr == "" {
				controller.WriteProblemDetailsError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "Missing required 5-layer security headers (X-API-KEY-ID, X-SIGNATURE, X-NONCE, X-EXPIRES-AT)")
				return
			}

			// Parse expiresAt timestamp
			expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
			if err != nil {
				controller.WriteProblemDetailsError(w, r, http.StatusBadRequest, "INVALID_HEADER", "X-EXPIRES-AT must be a valid Unix timestamp")
				return
			}

			// Layer 2: Client-Set TTL Expiry Check (with 30s clock skew buffer)
			maxTTL := int64(900) // 15 minutes max TTL window
			if err := security.ValidatePayloadTTL(expiresAt, maxTTL); err != nil {
				controller.WriteProblemDetailsError(w, r, http.StatusUnauthorized, "EXPIRED_TOKEN", err.Error())
				return
			}

			// Lookup registered API Key Details
			keyDetails, exists := keyStore[keyID]
			if !exists || !keyDetails.IsActive {
				controller.WriteProblemDetailsError(w, r, http.StatusUnauthorized, "INVALID_API_KEY", "API Key ID is invalid or inactive")
				return
			}

			// Parse Ed25519 Public Key
			pubKey, err := security.ParseEd25519PublicKeyBase64(keyDetails.PublicKeyBase64)
			if err != nil {
				controller.WriteProblemDetailsError(w, r, http.StatusInternalServerError, "KEY_PARSE_ERROR", "Failed to parse registered public key")
				return
			}

			// Layer 4: Real TCP Socket / Trusted Proxy IP Check
			clientIP := GetRealClientIP(r)
			if config.AppConfig.EnforceStrictIPBinding || len(keyDetails.WhitelistedIPs) > 0 {
				if !ValidateIPWhitelist(clientIP, keyDetails.WhitelistedIPs) {
					controller.WriteProblemDetailsError(w, r, http.StatusForbidden, "IP_NOT_ALLOWED", fmt.Sprintf("Client IP %s is not in the whitelisted access list", clientIP))
					return
				}
			}

			// Layer 3: Nonce Replay Check (Fail-Closed)
			if replayStore != nil {
				ttlSeconds := time.Duration(expiresAt-time.Now().Unix()+30) * time.Second
				if ttlSeconds < 10*time.Second {
					ttlSeconds = 10 * time.Second
				}

				setOk, err := replayStore.CheckAndSet(r.Context(), keyID, nonce, ttlSeconds)
				if err != nil || !setOk {
					controller.WriteProblemDetailsError(w, r, http.StatusUnauthorized, "REPLAY_ATTACK_DETECTED", "Duplicate request nonce detected (replay attack blocked)")
					return
				}
			}

			// Read request body to construct canonical signature message
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				controller.WriteProblemDetailsError(w, r, http.StatusBadRequest, "INVALID_BODY", "Failed to read request payload body")
				return
			}
			// Restore r.Body so downstream controllers can read it
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// Construct canonical message: Method + Path + Nonce + ExpiresAt + Body
			canonicalMsg := fmt.Sprintf("%s\n%s\n%s\n%d\n%s", r.Method, r.URL.Path, nonce, expiresAt, string(bodyBytes))

			// Decode Ed25519 signature
			sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
			if err != nil {
				controller.WriteProblemDetailsError(w, r, http.StatusBadRequest, "INVALID_SIGNATURE_FORMAT", "Signature must be base64 encoded")
				return
			}

			// Layer 1: Ed25519 Asymmetric Signature Check
			if !security.VerifyEd25519Signature(pubKey, []byte(canonicalMsg), sigBytes) {
				controller.WriteProblemDetailsError(w, r, http.StatusUnauthorized, "INVALID_SIGNATURE", "Ed25519 cryptographic signature verification failed")
				return
			}

			// Layer 5: Inject Tenant Context & Security Context
			ctx := r.Context()
			if keyDetails.InstitutionID != uuid.Nil {
				tenantData := &pkgctx.TenantData{
					InstitutionID: keyDetails.InstitutionID,
					Role:          "API_SERVICE",
				}
				ctx = pkgctx.WithTenant(ctx, tenantData)
			}

			bctx := &BulletproofSecurityContext{
				KeyID:         keyID,
				InstitutionID: keyDetails.InstitutionID.String(),
				ClientIP:      clientIP,
				ExpiresAt:     expiresAt,
				PublicKey:     pubKey,
			}
			ctx = context.WithValue(ctx, BulletproofContextKey, bctx)

			// Proceed to downstream handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
