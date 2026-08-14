package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultMaxConcurrentWebhooks limits simultaneous outbound HTTP webhook delivery goroutines.
const DefaultMaxConcurrentWebhooks = 25

// WebhookEvent represents an event payload dispatched to registered subscriber webhooks.
type WebhookEvent struct {
	ID            string         `json:"id"`
	EventType     string         `json:"event_type"`
	InstitutionID string         `json:"institution_id"`
	ActorID       string         `json:"actor_id"`
	Timestamp     int64          `json:"timestamp"`
	Data          map[string]any `json:"data"`
}

// NewWebhookEvent constructs a new WebhookEvent with an assigned UUID and current timestamp.
func NewWebhookEvent(eventType, institutionID, actorID string, data map[string]any) *WebhookEvent {
	return &WebhookEvent{
		ID:            uuid.Must(uuid.NewV7()).String(),
		EventType:     eventType,
		InstitutionID: institutionID,
		ActorID:       actorID,
		Timestamp:     time.Now().UTC().Unix(),
		Data:          data,
	}
}

// WebhookDispatcher delivers audit and grant lifecycle events to external systems via signed HTTP webhooks.
type WebhookDispatcher struct {
	webhookURL string
	secretKey  string
	client     *http.Client
	sem        chan struct{}
	wg         sync.WaitGroup
	mu         sync.RWMutex
	closed     bool
}

// NewWebhookDispatcher creates a new WebhookDispatcher instance with bounded worker capacity.
func NewWebhookDispatcher(webhookURL, secretKey string) *WebhookDispatcher {
	return &WebhookDispatcher{
		webhookURL: webhookURL,
		secretKey:  secretKey,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		sem: make(chan struct{}, DefaultMaxConcurrentWebhooks),
	}
}

// ComputeSignature calculates the HMAC-SHA256 signature for a payload.
func (d *WebhookDispatcher) ComputeSignature(payload []byte) string {
	if d.secretKey == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(d.secretKey))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Dispatch sends a webhook event synchronously with HMAC-SHA256 signature authentication.
func (d *WebhookDispatcher) Dispatch(ctx context.Context, event *WebhookEvent) error {
	if d.webhookURL == "" || d.secretKey == "" {
		return nil // No-op if webhook URL or signing secret is not configured
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GrantSupport-Webhook/1.0")
	req.Header.Set("X-GrantSupport-Event", event.EventType)
	req.Header.Set("X-GrantSupport-Delivery", event.ID)

	signature := d.ComputeSignature(payload)
	if signature != "" {
		req.Header.Set("X-GrantSupport-Signature", signature)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook delivery failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with non-2xx status code: %d", resp.StatusCode)
	}

	return nil
}

// DispatchAsync sends a webhook event asynchronously with bounded concurrency and shutdown tracking.
func (d *WebhookDispatcher) DispatchAsync(event *WebhookEvent) {
	if d.webhookURL == "" || d.secretKey == "" {
		return
	}

	d.mu.RLock()
	if d.closed {
		d.mu.RUnlock()
		slog.Warn("Webhook dispatch skipped: dispatcher is closed",
			slog.String("event_type", event.EventType),
			slog.String("event_id", event.ID),
		)
		return
	}
	d.wg.Add(1)
	d.mu.RUnlock()

	go func() {
		defer d.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Webhook async dispatch panic recovered", slog.Any("panic", r))
			}
		}()

		// Acquire worker slot from bounded semaphore channel
		d.sem <- struct{}{}
		defer func() { <-d.sem }()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := d.Dispatch(ctx, event); err != nil {
			slog.Warn("Webhook asynchronous delivery warning",
				slog.String("event_type", event.EventType),
				slog.String("event_id", event.ID),
				slog.String("error", err.Error()),
			)
		}
	}()
}

// Close gracefully waits for in-flight async webhook deliveries to complete or until the context expires.
func (d *WebhookDispatcher) Close(ctx context.Context) error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
