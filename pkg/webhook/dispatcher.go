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
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// DefaultMaxConcurrentWebhooks limits simultaneous outbound HTTP webhook delivery goroutines.
const DefaultMaxConcurrentWebhooks = 25

// MaxWebhookQueueSize defines the hard capacity limit of the in-memory pending retry queue.
// This prevents unbounded memory growth during sustained downstream webhook receiver outages.
const MaxWebhookQueueSize = 5000

// MaxWebhookDeliveryAttempts defines the maximum number of delivery tries before dead-lettering.
const MaxWebhookDeliveryAttempts = 3

// DefaultRetryBackoffSchedule defines the delay before consecutive retry attempts.
var DefaultRetryBackoffSchedule = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	15 * time.Second,
}

// WebhookEvent represents an event payload dispatched to registered subscriber webhooks.
type WebhookEvent struct {
	ID            string         `json:"id"`
	EventType     string         `json:"event_type"`
	InstitutionID string         `json:"institution_id"`
	ActorID       string         `json:"actor_id"`
	Timestamp     int64          `json:"timestamp"`
	Data          map[string]any `json:"data"`
	Attempt       int            `json:"-"`
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
		Attempt:       0,
	}
}

// WebhookDispatcher delivers audit and grant lifecycle events to external systems via signed HTTP webhooks.
//
// Durability Boundary:
// Webhook retries are managed via an in-memory queue. In-flight or pending retries are ephemeral
// and will be lost if the server process crashes or restarts. For applications requiring strict
// transactional delivery, observe audit events via the REST API or configure highly available endpoints.
type WebhookDispatcher struct {
	webhookURL      string
	secretKey       string
	client          *http.Client
	sem             chan struct{}
	queue           chan *WebhookEvent
	stopChan        chan struct{}
	backoffSchedule []time.Duration
	wg              sync.WaitGroup
	mu              sync.RWMutex
	closed          bool
	droppedCount    uint64
}

// NewWebhookDispatcher creates a new WebhookDispatcher instance with bounded worker capacity and bounded retry buffer.
func NewWebhookDispatcher(webhookURL, secretKey string) *WebhookDispatcher {
	d := &WebhookDispatcher{
		webhookURL: webhookURL,
		secretKey:  secretKey,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		sem:             make(chan struct{}, DefaultMaxConcurrentWebhooks),
		queue:           make(chan *WebhookEvent, MaxWebhookQueueSize),
		stopChan:        make(chan struct{}),
		backoffSchedule: DefaultRetryBackoffSchedule,
	}

	// Start background queue processing worker
	d.wg.Add(1)
	go d.processQueue()

	return d
}

// SetBackoffSchedule overrides the default retry backoff schedule.
func (d *WebhookDispatcher) SetBackoffSchedule(schedule []time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.backoffSchedule = schedule
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

// DispatchAsync enqueues an event for asynchronous delivery with bounded queue safety and exponential backoff retries.
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
	d.mu.RUnlock()

	select {
	case d.queue <- event:
		// Enqueued successfully
	default:
		// Queue is full (MaxWebhookQueueSize reached): drop and log error to prevent unbounded memory growth
		atomic.AddUint64(&d.droppedCount, 1)
		slog.Error("ERROR [WEBHOOK_QUEUE_OVERFLOW] Webhook retry queue is full; dropping event to prevent memory exhaustion",
			slog.String("event_type", event.EventType),
			slog.String("event_id", event.ID),
			slog.Uint64("total_dropped", atomic.LoadUint64(&d.droppedCount)),
		)
	}
}

func (d *WebhookDispatcher) processQueue() {
	defer d.wg.Done()

	for event := range d.queue {
		d.sem <- struct{}{}
		d.wg.Add(1)
		go func(ev *WebhookEvent) {
			defer d.wg.Done()
			defer func() { <-d.sem }()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Webhook worker panic recovered", slog.Any("panic", r))
				}
			}()

			d.executeWithRetry(ev)
		}(event)
	}
}

func (d *WebhookDispatcher) executeWithRetry(event *WebhookEvent) {
	for attempt := 1; attempt <= MaxWebhookDeliveryAttempts; attempt++ {
		event.Attempt = attempt

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := d.Dispatch(ctx, event)
		cancel()

		if err == nil {
			// Successful delivery
			return
		}

		slog.Warn("Webhook asynchronous delivery attempt failed",
			slog.String("event_type", event.EventType),
			slog.String("event_id", event.ID),
			slog.Int("attempt", attempt),
			slog.Int("max_attempts", MaxWebhookDeliveryAttempts),
			slog.String("error", err.Error()),
		)

		if attempt < MaxWebhookDeliveryAttempts {
			d.mu.RLock()
			schedule := d.backoffSchedule
			d.mu.RUnlock()

			backoff := schedule[attempt-1]
			select {
			case <-d.stopChan:
				return // Discard retry immediately upon shutdown timeout
			case <-time.After(backoff):
			}
		}
	}

	// Dead letter logging after exhausting all retry attempts
	slog.Warn("WARN [WEBHOOK_DEAD_LETTER] Webhook event discarded after exhausting retry attempts",
		slog.String("event_type", event.EventType),
		slog.String("event_id", event.ID),
	)
}

// DroppedCount returns the total number of dropped events due to queue capacity saturation.
func (d *WebhookDispatcher) DroppedCount() uint64 {
	return atomic.LoadUint64(&d.droppedCount)
}

// Close gracefully stops accepting new events, closes the queue, and waits for active deliveries to drain.
func (d *WebhookDispatcher) Close(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	close(d.queue)
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
		d.mu.Lock()
		select {
		case <-d.stopChan:
		default:
			close(d.stopChan)
		}
		d.mu.Unlock()
		return ctx.Err()
	}
}
