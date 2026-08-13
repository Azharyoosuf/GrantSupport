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
	"time"

	"github.com/google/uuid"
)

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
		ID:            uuid.New().String(),
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
}

// NewWebhookDispatcher creates a new WebhookDispatcher instance.
func NewWebhookDispatcher(webhookURL, secretKey string) *WebhookDispatcher {
	return &WebhookDispatcher{
		webhookURL: webhookURL,
		secretKey:  secretKey,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
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
	if d.webhookURL == "" {
		return nil // No-op if webhook is not configured
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

	if signature := d.ComputeSignature(payload); signature != "" {
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

// DispatchAsync sends a webhook event asynchronously in a background goroutine.
func (d *WebhookDispatcher) DispatchAsync(event *WebhookEvent) {
	if d.webhookURL == "" {
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Webhook async dispatch panic recovered", slog.Any("panic", r))
			}
		}()

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
