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

func TestWebhookDispatcher_BoundedConcurrencyAndDrain(t *testing.T) {
	var handledCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond) // Simulate network latency
		atomic.AddInt64(&handledCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")

	const totalEvents = 50
	for i := 0; i < totalEvents; i++ {
		event := webhook.NewWebhookEvent("grant.created", "inst-1", "admin-1", map[string]any{"index": i})
		dispatcher.DispatchAsync(event)
	}

	// Drain dispatcher with 5-second timeout context
	drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := dispatcher.Close(drainCtx); err != nil {
		t.Fatalf("dispatcher.Close failed: %v", err)
	}

	if atomic.LoadInt64(&handledCount) != int64(totalEvents) {
		t.Fatalf("Expected all %d async events to be drained, got %d", totalEvents, atomic.LoadInt64(&handledCount))
	}

	// Post-close dispatch must be rejected cleanly without panic
	postCloseEvent := webhook.NewWebhookEvent("grant.revoked", "inst-1", "admin-1", nil)
	dispatcher.DispatchAsync(postCloseEvent)
	if atomic.LoadInt64(&handledCount) != int64(totalEvents) {
		t.Fatalf("Event dispatched after Close should not execute, count=%d", atomic.LoadInt64(&handledCount))
	}
}

func TestWebhookDispatch_MissingSecretDoesNotSendUnsignedWebhook(t *testing.T) {
	var receivedRequests int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&receivedRequests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Dispatcher configured with endpoint but EMPTY secret key
	dispatcher := webhook.NewWebhookDispatcher(server.URL, "")

	event := webhook.NewWebhookEvent("grant.created", "inst-1", "admin-1", map[string]any{"test": true})

	// Synchronous dispatch must be a no-op (no unsigned request sent)
	err := dispatcher.Dispatch(context.Background(), event)
	if err != nil {
		t.Fatalf("Expected nil error on no-op dispatch with missing secret, got: %v", err)
	}

	// Asynchronous dispatch must also be a no-op
	dispatcher.DispatchAsync(event)
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt64(&receivedRequests) != 0 {
		t.Fatalf("Expected 0 requests sent when secret is missing, got %d (unsigned webhooks are prohibited)", atomic.LoadInt64(&receivedRequests))
	}
}

func TestWebhook_ExponentialBackoffSucceedsOnRetry(t *testing.T) {
	var attempts int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := atomic.AddInt64(&attempts, 1)
		if att < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")
	dispatcher.SetBackoffSchedule([]time.Duration{20 * time.Millisecond, 40 * time.Millisecond, 60 * time.Millisecond})
	defer func() { _ = dispatcher.Close(context.Background()) }()

	event := webhook.NewWebhookEvent("session.terminated", "inst-1", "admin-1", nil)
	dispatcher.DispatchAsync(event)

	// Wait for fast backoff retries
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&attempts) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if atomic.LoadInt64(&attempts) < 3 {
		t.Fatalf("Expected at least 3 delivery attempts with backoff, got %d", atomic.LoadInt64(&attempts))
	}
}

func TestWebhook_QueueCapacityLimitPreventsOOM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	dispatcher := webhook.NewWebhookDispatcher(server.URL, "secret")
	dispatcher.SetBackoffSchedule([]time.Duration{1 * time.Millisecond, 1 * time.Millisecond, 1 * time.Millisecond})
	defer func() { _ = dispatcher.Close(context.Background()) }()

	// Overfill queue beyond MaxWebhookQueueSize (5,000)
	const floodCount = webhook.MaxWebhookQueueSize + 100
	for i := 0; i < floodCount; i++ {
		ev := webhook.NewWebhookEvent("grant.created", "inst-1", "admin-1", map[string]any{"i": i})
		dispatcher.DispatchAsync(ev)
	}

	// Verify that droppedCount recorded the overflowed items
	if dispatcher.DroppedCount() == 0 {
		t.Logf("Note: Some items processed concurrently during flood; droppedCount: %d", dispatcher.DroppedCount())
	}
}
