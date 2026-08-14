package grantsupport_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/adapters/revocation"
	"grantsupport/pkg/config"
	"grantsupport/pkg/controller"
	"grantsupport/pkg/domain"
	"grantsupport/pkg/middleware"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
)

// TestHTTPS_EndToEndWorkflow verifies the full GrantSupport API workflow executed over native HTTPS/TLS.
func TestHTTPS_EndToEndWorkflow(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	// 1. Generate ephemeral TLS certificates
	tlsCert, certPEM, keyPEM, err := security.GenerateTestTLSCertificate("127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("Failed to generate test TLS certificate: %v", err)
	}

	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	_ = os.WriteFile(certFile, certPEM, 0600)
	_ = os.WriteFile(keyFile, keyPEM, 0600)

	tlsConfig, err := security.NewServerTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	// 2. Initialize in-memory database and services
	db, err := sql.Open("sqlite", "file:https_workflow_test?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	if err := repository.CreateCapabilityTables(ctx, db, "sqlite"); err != nil {
		t.Fatalf("CreateCapabilityTables failed: %v", err)
	}

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Schema.Create failed: %v", err)
	}

	grantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewSQLLockStore(db, "sqlite")
	revStore := revocation.NewSQLRevocationStore(db, "sqlite")

	svc := service.NewGrantSupportService(grantRepo, auditRepo, lockStore)
	svc.SetRevocationStore(revStore)
	ctrl := controller.NewSupportGrantController(svc)

	// 3. Build router with security headers
	r := chi.NewRouter()
	r.Use(middleware.SecurityHeadersMiddleware)

	r.Post("/api/v1/auth/support/login", controller.CatchAsync(ctrl.SupportLogin))

	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(revStore))
		r.Use(middleware.RequireRoles("ADMIN", "ADMINISTRATOR", "OWNER"))
		r.Post("/api/v1/auth/support/grant", controller.CatchAsync(ctrl.GrantSupport))
		r.Post("/api/v1/auth/support/revoke", controller.CatchAsync(ctrl.RevokeSupport))
	})

	r.Group(func(r chi.Router) {
		r.Use(middleware.NewAuthMiddleware(revStore))
		r.Use(middleware.RequireRoles("SUPPORT_AGENT"))
		r.Post("/api/v1/auth/support/logout", controller.CatchAsync(ctrl.SupportLogout))
	})

	// 4. Start HTTPS Test Server
	server := httptest.NewUnstartedServer(r)
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	// 5. Construct TLS client trusting the test certificate
	certPool := x509.NewCertPool()
	leafCert, _ := x509.ParseCertificate(tlsCert.Certificate[0])
	certPool.AddCert(leafCert)

	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	instID := domain.NewUUID()
	adminID := domain.NewUUID()
	agentID := domain.NewUUID()

	adminToken, err := security.GenerateJWTWithVersion(adminID.String(), instID.String(), "ADMIN", "FULL_ACCESS", 1, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWTWithVersion failed: %v", err)
	}

	// 6. Execute POST /api/v1/auth/support/grant over HTTPS
	grantBody, _ := json.Marshal(map[string]any{
		"durationMinutes": 60,
		"scope":           "BILLING_ONLY",
	})
	req, _ := http.NewRequest("POST", server.URL+"/api/v1/auth/support/grant", bytes.NewBuffer(grantBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS POST /grant failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201 Created over HTTPS, got %d: %s", resp.StatusCode, string(respBody))
	}

	// Verify HTTP/2 or HTTP/1.1 protocol negotiation
	if resp.Proto != "HTTP/2.0" && resp.Proto != "HTTP/1.1" {
		t.Fatalf("Expected HTTP/2.0 or HTTP/1.1 protocol, got: %s", resp.Proto)
	}

	// Verify Security Headers on HTTPS response
	if ct := resp.Header.Get("X-Content-Type-Options"); ct != "nosniff" {
		t.Errorf("Expected X-Content-Type-Options 'nosniff', got '%s'", ct)
	}

	var grantResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&grantResp)
	if grantResp.Token == "" {
		t.Fatal("Expected non-empty support grant token")
	}

	// 7. Execute POST /api/v1/auth/support/login over HTTPS
	loginBody, _ := json.Marshal(map[string]any{
		"token":   grantResp.Token,
		"agentId": agentID.String(),
	})
	req, _ = http.NewRequest("POST", server.URL+"/api/v1/auth/support/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS POST /login failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200 OK over HTTPS, got %d: %s", resp.StatusCode, string(respBody))
	}

	var loginResp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&loginResp)
	if loginResp.AccessToken == "" {
		t.Fatal("Expected non-empty access token")
	}

	// 8. Execute POST /api/v1/auth/support/logout over HTTPS
	req, _ = http.NewRequest("POST", server.URL+"/api/v1/auth/support/logout", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS POST /logout failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for logout over HTTPS, got %d", resp.StatusCode)
	}
}

// TestHTTPS_NativeStartupAndHTTPRedirect verifies multi-listener HTTP-to-HTTPS redirection logic.
func TestHTTPS_NativeStartupAndHTTPRedirect(t *testing.T) {
	origConfig := config.AppConfig
	defer func() { config.AppConfig = origConfig }()

	config.AppConfig = &config.Config{
		TLSEnabled:          true,
		HTTPSPort:           "8443",
		HTTPToHTTPSRedirect: true,
	}

	redirectServer := httptest.NewServer(middleware.HTTPToHTTPSRedirectHandler("8443"))
	defer redirectServer.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirect automatically
		},
	}

	resp, err := client.Get(redirectServer.URL + "/health")
	if err != nil {
		t.Fatalf("Redirect request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("Expected 308 Permanent Redirect from HTTP listener, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if loc == "" || loc[:8] != "https://" {
		t.Fatalf("Expected Location starting with 'https://', got '%s'", loc)
	}
}
