package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"grantsupport/pkg/adapters/lock"
	"grantsupport/pkg/repository"
	"grantsupport/pkg/security"
	"grantsupport/pkg/service"
	"grantsupport/pkg/webhook"
)

func TestWebhookSignatureComputation(t *testing.T) {
	secret := "test_webhook_secret_key_123"
	dispatcher := webhook.NewWebhookDispatcher("http://localhost:9999", secret)

	payload := []byte(`{"event":"test"}`)
	sig := dispatcher.ComputeSignature(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if sig != expectedSig {
		t.Fatalf("ComputeSignature = %s, expected %s", sig, expectedSig)
	}
}

func TestWebhookDispatchDelivery(t *testing.T) {
	var receivedEvent webhook.WebhookEvent
	var receivedSignature string
	var receivedHeaderEvent string
	var receivedDeliveryID string

	secret := "secret_key_abc_456"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSignature = r.Header.Get("X-GrantSupport-Signature")
		receivedHeaderEvent = r.Header.Get("X-GrantSupport-Event")
		receivedDeliveryID = r.Header.Get("X-GrantSupport-Delivery")

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedEvent)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, secret)

	event := webhook.NewWebhookEvent("grant.created", "inst-111", "admin-222", map[string]any{
		"scope": "READ_ONLY",
	})

	err := dispatcher.Dispatch(context.Background(), event)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if receivedHeaderEvent != "grant.created" {
		t.Errorf("Expected X-GrantSupport-Event = grant.created, got %s", receivedHeaderEvent)
	}
	if receivedDeliveryID != event.ID {
		t.Errorf("Expected X-GrantSupport-Delivery = %s, got %s", event.ID, receivedDeliveryID)
	}
	if !strings.HasPrefix(receivedSignature, "sha256=") {
		t.Errorf("Expected signature with sha256= prefix, got %s", receivedSignature)
	}
	if receivedEvent.InstitutionID != "inst-111" || receivedEvent.ActorID != "admin-222" {
		t.Errorf("Unexpected event body received: %+v", receivedEvent)
	}
}

func TestWebhookDispatchAsync(t *testing.T) {
	var hitCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hitCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")

	event := webhook.NewWebhookEvent("grant.claimed", "inst-111", "agent-333", map[string]any{
		"scope": "FULL_ACCESS",
	})

	dispatcher.DispatchAsync(event)

	// Wait up to 1 second for background delivery
	for i := 0; i < 20; i++ {
		if atomic.LoadInt64(&hitCount) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if atomic.LoadInt64(&hitCount) != 1 {
		t.Fatalf("Expected async webhook to be delivered, got %d hits", atomic.LoadInt64(&hitCount))
	}
}

func TestWebhookDestinationFailure500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal_server_error"}`))
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")
	event := webhook.NewWebhookEvent("grant.revoked", "inst-1", "admin-1", nil)

	err := dispatcher.Dispatch(context.Background(), event)
	if err == nil {
		t.Fatal("Expected Dispatch to return error on HTTP 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "non-2xx status code: 500") {
		t.Fatalf("Unexpected error message: %v", err)
	}
}

func TestWebhookConnectionRefused(t *testing.T) {
	// Point to closed port
	dispatcher := webhook.NewWebhookDispatcher("http://127.0.0.1:59999/nonexistent-webhook", "secret")
	event := webhook.NewWebhookEvent("grant.created", "inst-1", "admin-1", nil)

	err := dispatcher.Dispatch(context.Background(), event)
	if err == nil {
		t.Fatal("Expected network error on connection refused, got nil")
	}
}

func TestWebhookTimeoutExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")
	event := webhook.NewWebhookEvent("grant.created", "inst-1", "admin-1", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := dispatcher.Dispatch(ctx, event)
	if err == nil {
		t.Fatal("Expected context deadline exceeded error on timeout, got nil")
	}
}

func TestGrantOperationIsolationFromWebhookFailure(t *testing.T) {
	ctx := context.Background()
	_ = security.SetupTestRSAKeys()

	db, err := sql.Open("sqlite", "file:webhook_isolation_test?mode=memory&cache=shared&_pragma=foreign_keys(1)&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	baseRepo := repository.NewBaseRepositoryWithDB(db, "sqlite")
	if err := baseRepo.MasterClient.Schema.Create(ctx); err != nil {
		t.Fatalf("Schema creation failed: %v", err)
	}

	supportGrantRepo := repository.NewSupportGrantRepository(baseRepo)
	auditRepo := repository.NewSecurityAuditRepository(baseRepo)
	lockStore := lock.NewMemoryLockStore()

	svc := service.NewGrantSupportService(supportGrantRepo, auditRepo, lockStore)

	// Configure a failing webhook endpoint (HTTP 500)
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingServer.Close()

	failingDispatcher := webhook.NewWebhookDispatcher(failingServer.URL, "secret")
	svc.SetWebhookDispatcher(failingDispatcher)

	instID := uuid.New()
	adminID := uuid.New()
	agentID := uuid.New()

	// 1. CreateSupportGrant must succeed despite failing webhook
	rawToken, err := svc.CreateSupportGrant(ctx, instID, adminID, 60)
	if err != nil {
		t.Fatalf("CreateSupportGrant failed when webhook endpoint is 500: %v", err)
	}
	if rawToken == "" {
		t.Fatal("Expected non-empty raw grant token")
	}

	// 2. SupportLogin must succeed despite failing webhook
	returnedInstID, jwtToken, err := svc.SupportLogin(ctx, rawToken, agentID)
	if err != nil {
		t.Fatalf("SupportLogin failed when webhook endpoint is 500: %v", err)
	}
	if returnedInstID != instID || jwtToken == "" {
		t.Fatalf("Expected valid login result, got inst=%s, token=%s", returnedInstID, jwtToken)
	}

	// 3. RevokeSupportGrant must succeed despite failing webhook
	if err := svc.RevokeSupportGrant(ctx, instID, adminID); err != nil {
		t.Fatalf("RevokeSupportGrant failed when webhook endpoint is 500: %v", err)
	}

	// 4. Audit chain remains completely unbroken and valid
	valid, err := auditRepo.VerifyAuditChain(ctx, instID)
	if err != nil || !valid {
		t.Fatalf("Audit chain was corrupted after webhook failure: valid=%v, err=%v", valid, err)
	}
}
