package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/ratelimit"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/cache"
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

				grantSvc := service.NewGrantSupportService(grantRepo, auditRepo)
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

func TestEmbeddedEngineParityWithServer(t *testing.T) {
	if err := security.SetupTestRSAKeys(); err != nil {
		t.Fatalf("SetupTestRSAKeys failed: %v", err)
	}

	t.Run("with_redis_wires_redis_stores_and_explicit_options_win", func(t *testing.T) {
		valkeyURL := os.Getenv("VALKEY_CACHE_URL")
		if valkeyURL == "" {
			valkeyURL = "valkey://127.0.0.1:6379/0"
		}
		vc, err := cache.NewValkeyClient(valkeyURL)
		if err != nil {
			t.Fatalf("Failed to connect to live Valkey (%s): %v", valkeyURL, err)
		}
		t.Cleanup(func() { _ = vc.Close() })
		rdb := vc.Client

		ctx := context.Background()
		dsn := fmt.Sprintf("file:engine_redis_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.NewString())
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatalf("sql.Open failed: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })

		eng, err := grantsupport.NewEngine(
			grantsupport.WithDB(db, "sqlite"),
			grantsupport.WithRedis(rdb),
			grantsupport.WithAutoMigrate(true),
		)
		if err != nil {
			t.Fatalf("NewEngine failed: %v", err)
		}
		t.Cleanup(func() { _ = eng.Close() })

		instID := uuid.New()
		adminID := uuid.New()
		agentID := uuid.New()

		// 1. Prove RedisLockStore is used by Engine:
		// Pre-hold "lock:audit:<instID>" in Valkey and call CreateSupportGrant with a 60ms context timeout.
		// Because RedisLockStore sees the lock in Valkey, LogSecurityEvent times out and writes 0 audit events.
		auditLockKey := fmt.Sprintf("lock:audit:%s", instID.String())
		if err := rdb.Set(ctx, auditLockKey, "external-holder", 5*time.Second).Err(); err != nil {
			t.Fatalf("failed to seed audit lock in Valkey: %v", err)
		}
		shortCtx, cancel := context.WithTimeout(ctx, 60*time.Millisecond)
		_, _ = eng.CreateSupportGrant(shortCtx, instID, adminID, 30, "FULL_ACCESS", nil)
		cancel()
		_ = rdb.Del(ctx, auditLockKey).Val()

		eventsWhileLocked, err := eng.GetAuditEvents(ctx, instID, 10, 0)
		if err != nil {
			t.Fatalf("GetAuditEvents failed: %v", err)
		}
		if len(eventsWhileLocked) != 0 {
			t.Fatalf("expected 0 audit events while Valkey key %s was held (proving RedisLockStore is wired), got %d", auditLockKey, len(eventsWhileLocked))
		}

		// Now that the Valkey lock is released, CreateSupportGrant succeeds and writes the audit event:
		rawToken, err := eng.CreateSupportGrant(ctx, instID, adminID, 30, "FULL_ACCESS", nil)
		if err != nil {
			t.Fatalf("CreateSupportGrant failed: %v", err)
		}
		eventsAfterUnlock, err := eng.GetAuditEvents(ctx, instID, 10, 0)
		if err != nil || len(eventsAfterUnlock) != 1 {
			t.Fatalf("expected 1 audit event after Valkey lock was released, got %d (err=%v)", len(eventsAfterUnlock), err)
		}

		// 2. Prove RedisRateLimiter is used by Engine.HTTPHandler():
		handler := eng.HTTPHandler()
		uniqueIP := fmt.Sprintf("198.51.100.%d", 100+(instID[0]%100))
		rateKey := fmt.Sprintf("ratelimit:ip:%s:/api/v1/auth/support/login", uniqueIP)
		_ = rdb.Del(ctx, rateKey).Val()
		t.Cleanup(func() { _ = rdb.Del(ctx, rateKey).Val() })

		loginBody, _ := json.Marshal(map[string]string{
			"token":   rawToken,
			"agentId": agentID.String(),
		})
		loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/support/login", bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")
		loginReq.RemoteAddr = uniqueIP + ":54321"
		loginRec := httptest.NewRecorder()
		handler.ServeHTTP(loginRec, loginReq)
		if loginRec.Code != http.StatusOK {
			t.Fatalf("login failed: %d %s", loginRec.Code, loginRec.Body.String())
		}

		rateVal, err := rdb.Get(ctx, rateKey).Result()
		if err != nil || rateVal != "1" {
			t.Fatalf("expected Valkey key %q to equal \"1\" (proving RedisRateLimiter is used), got val=%q err=%v", rateKey, rateVal, err)
		}

		// 3. Prove RedisRevocationStore is used by Engine:
		revKey := fmt.Sprintf("cache:%s:user:security:%s", instID.String(), agentID.String())
		_ = rdb.Del(ctx, revKey).Val()
		t.Cleanup(func() { _ = rdb.Del(ctx, revKey).Val() })

		if err := eng.RevokeSupportGrant(ctx, instID, adminID); err != nil {
			t.Fatalf("RevokeSupportGrant failed: %v", err)
		}
		revVal, err := rdb.Get(ctx, revKey).Result()
		if err != nil || revVal != "2" {
			t.Fatalf("expected Valkey key %q to equal \"2\" (proving RedisRevocationStore is used), got val=%q err=%v", revKey, revVal, err)
		}

		// 4. Prove explicit store options win over WithRedis(rdb):
		dsnExplicit := fmt.Sprintf("file:engine_explicit_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.NewString())
		dbExplicit, err := sql.Open("sqlite", dsnExplicit)
		if err != nil {
			t.Fatalf("sql.Open failed: %v", err)
		}
		t.Cleanup(func() { _ = dbExplicit.Close() })

		memLock := lock.NewMemoryLockStore()
		sqlRev := revocation.NewSQLRevocationStore(dbExplicit, "sqlite")
		memRate := ratelimit.NewMemoryRateLimiter()

		engExplicit, err := grantsupport.NewEngine(
			grantsupport.WithDB(dbExplicit, "sqlite"),
			grantsupport.WithRedis(rdb),
			grantsupport.WithLockStore(memLock),
			grantsupport.WithRevocationStore(sqlRev),
			grantsupport.WithRateLimiter(memRate),
			grantsupport.WithAutoMigrate(true),
		)
		if err != nil {
			t.Fatalf("NewEngine with explicit stores failed: %v", err)
		}
		t.Cleanup(func() { _ = engExplicit.Close() })

		instID2 := uuid.New()
		adminID2 := uuid.New()
		agentID2 := uuid.New()
		tok2, err := engExplicit.CreateSupportGrant(ctx, instID2, adminID2, 30, "FULL_ACCESS", nil)
		if err != nil {
			t.Fatalf("CreateSupportGrant failed: %v", err)
		}
		_, _, err = engExplicit.SupportLogin(ctx, tok2, agentID2)
		if err != nil {
			t.Fatalf("SupportLogin failed: %v", err)
		}
		if err := engExplicit.RevokeSupportGrant(ctx, instID2, adminID2); err != nil {
			t.Fatalf("RevokeSupportGrant failed: %v", err)
		}
		revKey2 := fmt.Sprintf("cache:%s:user:security:%s", instID2.String(), agentID2.String())
		if exists := rdb.Exists(ctx, revKey2).Val(); exists != 0 {
			t.Fatalf("expected explicit SQLRevocationStore to win over WithRedis, but Valkey key %s was written", revKey2)
		}
	})

	t.Run("security_headers_match_between_engine_and_server", func(t *testing.T) {
		prevCfg := config.AppConfig
		t.Cleanup(func() { config.AppConfig = prevCfg })
		config.AppConfig = &config.Config{
			TrustedProxies:        []string{"10.0.0.1"},
			HSTSEnabled:           true,
			HSTSMaxAge:            31536000,
			HSTSIncludeSubdomains: true,
		}

		factories := fullRouterFactories()
		engHandler, _ := factories[0].setup(t)
		srvHandler, _ := factories[1].setup(t)

		reqEng := httptest.NewRequest(http.MethodGet, "/health/live", nil)
		reqEng.RemoteAddr = "10.0.0.1:443"
		reqEng.Header.Set("X-Forwarded-Proto", "https")
		recEng := httptest.NewRecorder()
		engHandler.ServeHTTP(recEng, reqEng)

		reqSrv := httptest.NewRequest(http.MethodGet, "/health/live", nil)
		reqSrv.RemoteAddr = "10.0.0.1:443"
		reqSrv.Header.Set("X-Forwarded-Proto", "https")
		recSrv := httptest.NewRecorder()
		srvHandler.ServeHTTP(recSrv, reqSrv)

		expectedHeaders := []string{
			"X-Content-Type-Options",
			"X-Frame-Options",
			"Referrer-Policy",
			"Strict-Transport-Security",
		}
		for _, hdr := range expectedHeaders {
			engVal := recEng.Header().Get(hdr)
			srvVal := recSrv.Header().Get(hdr)
			if srvVal == "" {
				t.Fatalf("server router missing expected security header %s", hdr)
			}
			if engVal != srvVal {
				t.Fatalf("security header %s mismatch: Engine.HTTPHandler()=%q vs Server=%q", hdr, engVal, srvVal)
			}
		}
	})

	t.Run("webhook_dispatcher_starts_only_when_both_url_and_secret_are_set", func(t *testing.T) {
		var hits atomic.Int32
		hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer hookSrv.Close()

		ctx := context.Background()
		dsn1 := fmt.Sprintf("file:eng_hook_nosecret_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.NewString())
		db1, err := sql.Open("sqlite", dsn1)
		if err != nil {
			t.Fatalf("sql.Open failed: %v", err)
		}
		defer db1.Close()

		// URL without secret -> webhookDispatcher field on Engine must remain nil
		engNoSecret, err := grantsupport.NewEngine(
			grantsupport.WithDB(db1, "sqlite"),
			grantsupport.WithWebhook(hookSrv.URL, ""),
			grantsupport.WithAutoMigrate(true),
		)
		if err != nil {
			t.Fatalf("NewEngine failed: %v", err)
		}
		defer engNoSecret.Close()

		val := reflect.ValueOf(engNoSecret).Elem().FieldByName("webhookDispatcher")
		if !val.IsNil() {
			t.Fatalf("expected Engine.webhookDispatcher to be nil when WebhookSecret is empty, but it was initialized")
		}

		// URL + secret -> webhookDispatcher is initialized and delivers event
		dsn2 := fmt.Sprintf("file:eng_hook_withsecret_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.NewString())
		db2, err := sql.Open("sqlite", dsn2)
		if err != nil {
			t.Fatalf("sql.Open failed: %v", err)
		}
		defer db2.Close()

		engWithSecret, err := grantsupport.NewEngine(
			grantsupport.WithDB(db2, "sqlite"),
			grantsupport.WithWebhook(hookSrv.URL, "test-hmac-secret"),
			grantsupport.WithAutoMigrate(true),
		)
		if err != nil {
			t.Fatalf("NewEngine failed: %v", err)
		}
		_, err = engWithSecret.CreateSupportGrant(ctx, uuid.New(), uuid.New(), 30, "FULL_ACCESS", nil)
		if err != nil {
			t.Fatalf("CreateSupportGrant failed: %v", err)
		}
		_ = engWithSecret.Close()

		if hits.Load() == 0 {
			t.Fatalf("expected webhook to be delivered when both URL and secret are configured")
		}
	})

	t.Run("route_table_parity_between_engine_and_server", func(t *testing.T) {
		factories := fullRouterFactories()
		engHandler, _ := factories[0].setup(t)
		srvHandler, _ := factories[1].setup(t)

		collectRoutes := func(h http.Handler) []string {
			r, ok := h.(chi.Routes)
			if !ok {
				t.Fatalf("handler %T does not implement chi.Routes", h)
			}
			var routes []string
			err := chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
				routes = append(routes, fmt.Sprintf("%s %s", method, route))
				return nil
			})
			if err != nil {
				t.Fatalf("chi.Walk failed: %v", err)
			}
			sort.Strings(routes)
			return routes
		}

		engRoutes := collectRoutes(engHandler)
		srvRoutes := collectRoutes(srvHandler)

		if !reflect.DeepEqual(engRoutes, srvRoutes) {
			t.Fatalf("route table mismatch between Engine.HTTPHandler() and Server router:\nEngine: %v\nServer: %v", engRoutes, srvRoutes)
		}
	})
}

func TestValkeyCacheURLUnsetDoesNotDialLocalValkey(t *testing.T) {
	prevCfg := config.AppConfig
	prevEnv, hadEnv := os.LookupEnv("VALKEY_CACHE_URL")
	t.Cleanup(func() {
		config.AppConfig = prevCfg
		if hadEnv {
			_ = os.Setenv("VALKEY_CACHE_URL", prevEnv)
		} else {
			_ = os.Unsetenv("VALKEY_CACHE_URL")
		}
	})

	_ = os.Unsetenv("VALKEY_CACHE_URL")
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.ValkeyCacheURL != "" {
		t.Fatalf("expected cfg.ValkeyCacheURL to be empty when VALKEY_CACHE_URL is unset, got %q", cfg.ValkeyCacheURL)
	}

	dsn := fmt.Sprintf("file:server_no_valkey_%s?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1", uuid.NewString())
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	if err := repository.CreateCapabilityTables(context.Background(), db, "sqlite"); err != nil {
		t.Fatalf("CreateCapabilityTables failed: %v", err)
	}

	_, _, _, redisClient := initCapabilityStores(cfg, db, "sqlite")
	if redisClient != nil {
		_ = redisClient.Close()
		t.Fatalf("expected redisClient to be nil when VALKEY_CACHE_URL is unset, but server dialed 127.0.0.1:6379")
	}

	healthCtrl := controller.NewHealthController(grantsupport.Version, db, redisClient)
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()
	controller.CatchAsync(healthCtrl.Ready).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /health/ready, got %d: %s", rec.Code, rec.Body.String())
	}
	var readyResp struct {
		Mode   string `json:"mode"`
		Valkey string `json:"valkey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &readyResp); err != nil {
		t.Fatalf("failed to decode /health/ready response: %v", err)
	}
	if readyResp.Mode != "sql-only" || readyResp.Valkey != "NOT_CONFIGURED" {
		t.Fatalf("expected sql-only / NOT_CONFIGURED when VALKEY_CACHE_URL is unset, got mode=%q valkey=%q", readyResp.Mode, readyResp.Valkey)
	}
}
