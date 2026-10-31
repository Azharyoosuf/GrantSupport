package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/ratelimit"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/config"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/grantsupport"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

type routerFactory struct {
	name  string
	setup func(t *testing.T) (http.Handler, func(ctx context.Context, instID, adminID uuid.UUID, whitelistedIPs []string) string)
}

func fullRouterFactories() []routerFactory {
	return []routerFactory{
		{
			name: "Engine.HTTPHandler",
			setup: func(t *testing.T) (http.Handler, func(ctx context.Context, instID, adminID uuid.UUID, whitelistedIPs []string) string) {
				t.Helper()
				dsn := fmt.Sprintf("file:engine_router_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.NewString())
				db, err := sql.Open("sqlite", dsn)
				if err != nil {
					t.Fatalf("sql.Open failed: %v", err)
				}
				t.Cleanup(func() { _ = db.Close() })

				eng, err := grantsupport.NewEngine(
					grantsupport.WithDB(db, "sqlite"),
					grantsupport.WithAutoMigrate(true),
				)
				if err != nil {
					t.Fatalf("NewEngine failed: %v", err)
				}
				t.Cleanup(func() { _ = eng.Close() })

				createGrant := func(ctx context.Context, instID, adminID uuid.UUID, whitelistedIPs []string) string {
					tok, err := eng.CreateSupportGrant(ctx, instID, adminID, 30, "FULL_ACCESS", whitelistedIPs)
					if err != nil {
						t.Fatalf("CreateSupportGrant failed: %v", err)
					}
					return tok
				}
				return eng.HTTPHandler(), createGrant
			},
		},
		{
			name: "Server.Router",
			setup: func(t *testing.T) (http.Handler, func(ctx context.Context, instID, adminID uuid.UUID, whitelistedIPs []string) string) {
				t.Helper()
				dsn := fmt.Sprintf("file:server_router_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.NewString())
				db, err := sql.Open("sqlite", dsn)
				if err != nil {
					t.Fatalf("sql.Open failed: %v", err)
				}
				t.Cleanup(func() { _ = db.Close() })

				baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
				t.Cleanup(func() { _ = baseRepo.MasterClient.Close() })

				if err := baseRepo.MasterClient.Schema.Create(context.Background()); err != nil {
					t.Fatalf("Schema.Create failed: %v", err)
				}
				if err := repository.CreateCapabilityTables(context.Background(), db, "sqlite"); err != nil {
					t.Fatalf("CreateCapabilityTables failed: %v", err)
				}

				lockStore := lock.NewSQLLockStore(db, "sqlite")
				revStore := revocation.NewSQLRevocationStore(db, "sqlite")
				rateLimiter := ratelimit.NewMemoryRateLimiter()

				grantRepo := repository.NewSupportGrantRepository(baseRepo)
				auditRepo := repository.NewSecurityAuditRepository(baseRepo)
				auditRepo.SetLockStore(lockStore)

				grantSvc := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
				grantSvc.SetRevocationStore(revStore)

				grantCtrl := controller.NewSupportGrantController(grantSvc)
				auditSvc := service.NewSecurityAuditService(auditRepo)
				auditCtrl := controller.NewAuditController(auditSvc)
				jwksCtrl := controller.NewJWKSController()
				healthCtrl := controller.NewHealthController(grantsupport.Version, db, nil)

				router := newServerRouter(grantCtrl, auditCtrl, jwksCtrl, healthCtrl, revStore, rateLimiter)
				createGrant := func(ctx context.Context, instID, adminID uuid.UUID, whitelistedIPs []string) string {
					tok, err := grantSvc.CreateSupportGrantScoped(ctx, instID, adminID, 30, "FULL_ACCESS", whitelistedIPs)
					if err != nil {
						t.Fatalf("CreateSupportGrantScoped failed: %v", err)
					}
					return tok
				}
				return router, createGrant
			},
		},
	}
}

func TestClientIPSpoofingAndTrustedProxies_FullRouters(t *testing.T) {
	if err := security.SetupTestRSAKeys(); err != nil {
		t.Fatalf("SetupTestRSAKeys failed: %v", err)
	}

	prevCfg := config.AppConfig
	t.Cleanup(func() {
		config.AppConfig = prevCfg
	})

	for _, rf := range fullRouterFactories() {
		t.Run(rf.name, func(t *testing.T) {
			t.Run("a_untrusted_peer_cannot_bypass_whitelisted_ips_at_login", func(t *testing.T) {
				config.AppConfig = &config.Config{
					TrustedProxies: []string{"10.0.0.1"},
				}
				handler, createGrant := rf.setup(t)
				ctx := context.Background()
				instID := uuid.New()
				adminID := uuid.New()
				agentID := uuid.New()

				token := createGrant(ctx, instID, adminID, []string{"198.51.100.10"})

				spoofAttempts := []struct {
					name    string
					headers map[string]string
				}{
					{
						name:    "X-Real-IP",
						headers: map[string]string{"X-Real-IP": "198.51.100.10"},
					},
					{
						name:    "X-Forwarded-For",
						headers: map[string]string{"X-Forwarded-For": "198.51.100.10"},
					},
					{
						name:    "CF-Connecting-IP",
						headers: map[string]string{"CF-Connecting-IP": "198.51.100.10"},
					},
					{
						name: "X-Real-IP_spoofing_trusted_proxy_plus_CF-Connecting-IP",
						headers: map[string]string{
							"X-Real-IP":        "10.0.0.1",
							"CF-Connecting-IP": "198.51.100.10",
						},
					},
				}

				for _, attempt := range spoofAttempts {
					body, _ := json.Marshal(map[string]string{
						"token":   token,
						"agentId": agentID.String(),
					})
					req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					req.RemoteAddr = "203.0.113.99:54321" // Untrusted peer outside TrustedProxies
					for k, v := range attempt.headers {
						req.Header.Set(k, v)
					}

					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)

					if rec.Code != http.StatusUnauthorized {
						t.Fatalf("[%s] expected 401 Unauthorized when untrusted peer spoofs %v, got %d (body: %s)",
							attempt.name, attempt.headers, rec.Code, rec.Body.String())
					}
				}
			})

			t.Run("b_untrusted_peer_cannot_bypass_per_ip_rate_limiting", func(t *testing.T) {
				config.AppConfig = &config.Config{
					TrustedProxies: []string{"10.0.0.1"},
				}
				handler, _ := rf.setup(t)
				agentID := uuid.New()

				// /api/v1/auth/support/login has a limit of 10 requests per 60s per IP.
				// Send 10 requests from the same untrusted peer (203.0.113.88) while rotating spoofed headers on every request.
				for i := 1; i <= 10; i++ {
					body, _ := json.Marshal(map[string]string{
						"token":   fmt.Sprintf("%s_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", uuid.NewString()),
						"agentId": agentID.String(),
					})
					req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					req.RemoteAddr = fmt.Sprintf("203.0.113.88:%d", 50000+i)
					req.Header.Set("X-Real-IP", fmt.Sprintf("192.0.2.%d", i))
					req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i))
					req.Header.Set("CF-Connecting-IP", fmt.Sprintf("192.0.2.%d", i))

					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)

					if rec.Code == http.StatusTooManyRequests {
						t.Fatalf("request %d should not be rate limited yet, got 429", i)
					}
				}

				// 11th request from 203.0.113.88 with a brand-new spoofed IP must be rejected with 429 Too Many Requests.
				body, _ := json.Marshal(map[string]string{
					"token":   fmt.Sprintf("%s_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", uuid.NewString()),
					"agentId": agentID.String(),
				})
				req11 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(body))
				req11.Header.Set("Content-Type", "application/json")
				req11.RemoteAddr = "203.0.113.88:50099"
				req11.Header.Set("X-Real-IP", "192.0.2.250")
				req11.Header.Set("X-Forwarded-For", "192.0.2.250")
				req11.Header.Set("CF-Connecting-IP", "192.0.2.250")

				rec11 := httptest.NewRecorder()
				handler.ServeHTTP(rec11, req11)

				if rec11.Code != http.StatusTooManyRequests {
					t.Fatalf("expected 429 Too Many Requests on 11th request from untrusted peer despite rotating spoofed IP headers, got %d (body: %s)",
						rec11.Code, rec11.Body.String())
				}
			})

			t.Run("c_trusted_proxy_headers_are_respected", func(t *testing.T) {
				config.AppConfig = &config.Config{
					TrustedProxies: []string{"10.0.0.0/24"},
				}
				handler, createGrant := rf.setup(t)
				ctx := context.Background()
				instID := uuid.New()
				adminID := uuid.New()
				agentID := uuid.New()

				headerCases := []struct {
					name      string
					headerKey string
					headerVal string
				}{
					{name: "X-Real-IP", headerKey: "X-Real-IP", headerVal: "198.51.100.10"},
					{name: "X-Forwarded-For", headerKey: "X-Forwarded-For", headerVal: "198.51.100.10, 10.0.0.5"},
					{name: "CF-Connecting-IP", headerKey: "CF-Connecting-IP", headerVal: "198.51.100.10"},
				}

				for _, tc := range headerCases {
					tok := createGrant(ctx, instID, adminID, []string{"198.51.100.10"})

					// First verify a non-whitelisted forwarded IP via trusted proxy is rejected
					badBody, _ := json.Marshal(map[string]string{"token": tok, "agentId": agentID.String()})
					badReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(badBody))
					badReq.Header.Set("Content-Type", "application/json")
					badReq.RemoteAddr = "10.0.0.5:443" // Inside TrustedProxies 10.0.0.0/24
					badReq.Header.Set(tc.headerKey, "198.51.100.99")

					badRec := httptest.NewRecorder()
					handler.ServeHTTP(badRec, badReq)
					if badRec.Code != http.StatusUnauthorized {
						t.Fatalf("[%s] expected 401 for non-whitelisted forwarded IP from trusted proxy, got %d", tc.name, badRec.Code)
					}

					// Now verify the whitelisted forwarded IP via trusted proxy is accepted
					okBody, _ := json.Marshal(map[string]string{"token": tok, "agentId": agentID.String()})
					okReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(okBody))
					okReq.Header.Set("Content-Type", "application/json")
					okReq.RemoteAddr = "10.0.0.5:443" // Inside TrustedProxies 10.0.0.0/24
					okReq.Header.Set(tc.headerKey, tc.headerVal)

					okRec := httptest.NewRecorder()
					handler.ServeHTTP(okRec, okReq)
					if okRec.Code != http.StatusOK {
						t.Fatalf("[%s] expected 200 OK for whitelisted forwarded IP from trusted proxy, got %d (body: %s)",
							tc.name, okRec.Code, okRec.Body.String())
					}
				}

				// Verify rate limiting behind a trusted proxy keys on the forwarded client IP, not the proxy IP:
				// Exhaust 10 attempts for forwarded IP 198.51.100.20 via proxy 10.0.0.5, then verify 198.51.100.21 is still allowed.
				for i := 1; i <= 10; i++ {
					b, _ := json.Marshal(map[string]string{
						"token":   fmt.Sprintf("%s_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", uuid.NewString()),
						"agentId": agentID.String(),
					})
					r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(b))
					r.Header.Set("Content-Type", "application/json")
					r.RemoteAddr = "10.0.0.5:443"
					r.Header.Set("X-Real-IP", "198.51.100.20")
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, r)
				}
				// 11th request for 198.51.100.20 via trusted proxy -> 429
				b11, _ := json.Marshal(map[string]string{
					"token":   fmt.Sprintf("%s_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", uuid.NewString()),
					"agentId": agentID.String(),
				})
				r11 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(b11))
				r11.Header.Set("Content-Type", "application/json")
				r11.RemoteAddr = "10.0.0.5:443"
				r11.Header.Set("X-Real-IP", "198.51.100.20")
				rec11 := httptest.NewRecorder()
				handler.ServeHTTP(rec11, r11)
				if rec11.Code != http.StatusTooManyRequests {
					t.Fatalf("expected 429 for 11th request of forwarded IP 198.51.100.20 via trusted proxy, got %d", rec11.Code)
				}

				// Different forwarded IP 198.51.100.21 via the same trusted proxy 10.0.0.5 -> NOT 429
				tokOther := createGrant(ctx, instID, adminID, []string{"198.51.100.21"})
				bOther, _ := json.Marshal(map[string]string{"token": tokOther, "agentId": agentID.String()})
				rOther := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(bOther))
				rOther.Header.Set("Content-Type", "application/json")
				rOther.RemoteAddr = "10.0.0.5:443"
				rOther.Header.Set("X-Real-IP", "198.51.100.21")
				recOther := httptest.NewRecorder()
				handler.ServeHTTP(recOther, rOther)
				if recOther.Code != http.StatusOK {
					t.Fatalf("expected 200 OK for different forwarded IP 198.51.100.21 via same trusted proxy, got %d", recOther.Code)
				}
			})
		})
	}
}
