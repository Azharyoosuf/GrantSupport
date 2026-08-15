package observability

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// MetricRegistry manages low-cardinality Prometheus metrics for GrantSupport.
// All labels are strictly bounded to prevent cardinality explosion or PII disclosure.
type MetricRegistry struct {
	mu sync.RWMutex

	// Counters
	grantsCreatedTotal uint64
	loginsTotal        map[string]*uint64 // status: "success", "failure"
	authFailuresTotal  map[string]*uint64 // reason: "token_expired", "token_revoked", "invalid_signature", "invalid_kid", "missing_claims", "insufficient_role"
	revocationsTotal   map[string]*uint64 // scope: "tenant", "agent", "session"
	rateLimitTotal     map[string]*uint64 // route: static normalized route name
	webhookDispatches  map[string]*uint64 // status: "delivered", "retrying", "dead_letter", "dropped_queue_full"
	httpRequestsTotal  map[string]*uint64 // key: route + ":" + statusCode

	// Gauges
	activeSessionsGauge int64
	dbConnectionsOpen   int64
	dbConnectionsInUse  int64

	// Histograms: duration in seconds
	requestDurations map[string]*histogram // key: route
}

type histogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

var defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0}

func newHistogram() *histogram {
	return &histogram{
		buckets: defaultBuckets,
		counts:  make([]uint64, len(defaultBuckets)),
	}
}

func (h *histogram) Observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.count++
	h.sum += value
	for i, b := range h.buckets {
		if value <= b {
			h.counts[i]++
		}
	}
}

// Global default registry singleton
var DefaultRegistry = NewMetricRegistry()

// NewMetricRegistry initializes an isolated Prometheus MetricRegistry.
func NewMetricRegistry() *MetricRegistry {
	r := &MetricRegistry{
		loginsTotal:       make(map[string]*uint64),
		authFailuresTotal: make(map[string]*uint64),
		revocationsTotal:  make(map[string]*uint64),
		rateLimitTotal:    make(map[string]*uint64),
		webhookDispatches: make(map[string]*uint64),
		httpRequestsTotal: make(map[string]*uint64),
		requestDurations:  make(map[string]*histogram),
	}

	// Pre-populate bounded labels
	for _, status := range []string{"success", "failure"} {
		var v uint64
		r.loginsTotal[status] = &v
	}
	for _, reason := range []string{"token_expired", "token_revoked", "invalid_signature", "invalid_kid", "missing_claims", "insufficient_role"} {
		var v uint64
		r.authFailuresTotal[reason] = &v
	}
	for _, scope := range []string{"tenant", "agent", "session"} {
		var v uint64
		r.revocationsTotal[scope] = &v
	}
	for _, status := range []string{"delivered", "retrying", "dead_letter", "dropped_queue_full"} {
		var v uint64
		r.webhookDispatches[status] = &v
	}

	return r
}

// IncGrantsCreated records a successfully generated support access grant.
func (r *MetricRegistry) IncGrantsCreated() {
	atomic.AddUint64(&r.grantsCreatedTotal, 1)
}

// IncLogins records a support agent login outcome ("success" or "failure").
func (r *MetricRegistry) IncLogins(status string) {
	r.mu.RLock()
	ptr, ok := r.loginsTotal[status]
	r.mu.RUnlock()
	if ok {
		atomic.AddUint64(ptr, 1)
	}
}

// IncAuthFailures records an authentication failure with a static reason code.
func (r *MetricRegistry) IncAuthFailures(reason string) {
	r.mu.RLock()
	ptr, ok := r.authFailuresTotal[reason]
	r.mu.RUnlock()
	if ok {
		atomic.AddUint64(ptr, 1)
	}
}

// IncRevocations records a revocation event ("tenant", "agent", or "session").
func (r *MetricRegistry) IncRevocations(scope string) {
	r.mu.RLock()
	ptr, ok := r.revocationsTotal[scope]
	r.mu.RUnlock()
	if ok {
		atomic.AddUint64(ptr, 1)
	}
}

// IncRateLimitExceeded records a rate-limit breach for a normalized route.
func (r *MetricRegistry) IncRateLimitExceeded(normalizedRoute string) {
	r.mu.Lock()
	ptr, ok := r.rateLimitTotal[normalizedRoute]
	if !ok {
		var v uint64
		ptr = &v
		r.rateLimitTotal[normalizedRoute] = ptr
	}
	r.mu.Unlock()
	atomic.AddUint64(ptr, 1)
}

// IncWebhookDispatches records a webhook delivery status.
func (r *MetricRegistry) IncWebhookDispatches(status string) {
	r.mu.RLock()
	ptr, ok := r.webhookDispatches[status]
	r.mu.RUnlock()
	if ok {
		atomic.AddUint64(ptr, 1)
	}
}

// RecordHTTPRequest tracks an HTTP request execution using a static normalized route and status code.
func (r *MetricRegistry) RecordHTTPRequest(normalizedRoute string, statusCode int, duration time.Duration) {
	key := normalizedRoute + ":" + strconv.Itoa(statusCode)

	r.mu.Lock()
	ptr, ok := r.httpRequestsTotal[key]
	if !ok {
		var v uint64
		ptr = &v
		r.httpRequestsTotal[key] = ptr
	}

	hist, histOk := r.requestDurations[normalizedRoute]
	if !histOk {
		hist = newHistogram()
		r.requestDurations[normalizedRoute] = hist
	}
	r.mu.Unlock()

	atomic.AddUint64(ptr, 1)
	hist.Observe(duration.Seconds())
}

// SetActiveSessions updates the active sessions gauge.
func (r *MetricRegistry) SetActiveSessions(count int64) {
	atomic.StoreInt64(&r.activeSessionsGauge, count)
}

// SetDBPoolStats updates database connection pool metrics.
func (r *MetricRegistry) SetDBPoolStats(open, inUse int) {
	atomic.StoreInt64(&r.dbConnectionsOpen, int64(open))
	atomic.StoreInt64(&r.dbConnectionsInUse, int64(inUse))
}

// Handler returns an http.HandlerFunc that renders metrics in standard Prometheus text exposition format.
func (r *MetricRegistry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var buf bytes.Buffer

		// 1. Grants Created
		buf.WriteString("# HELP grantsupport_grants_created_total Total number of delegated support grants generated.\n")
		buf.WriteString("# TYPE grantsupport_grants_created_total counter\n")
		buf.WriteString(fmt.Sprintf("grantsupport_grants_created_total %d\n\n", atomic.LoadUint64(&r.grantsCreatedTotal)))

		// 2. Logins Total
		buf.WriteString("# HELP grantsupport_logins_total Total support agent login attempts by outcome status.\n")
		buf.WriteString("# TYPE grantsupport_logins_total counter\n")
		r.mu.RLock()
		for status, ptr := range r.loginsTotal {
			buf.WriteString(fmt.Sprintf("grantsupport_logins_total{status=\"%s\"} %d\n", status, atomic.LoadUint64(ptr)))
		}
		r.mu.RUnlock()
		buf.WriteString("\n")

		// 3. Auth Failures Total
		buf.WriteString("# HELP grantsupport_auth_failures_total Total authentication failures by failure reason.\n")
		buf.WriteString("# TYPE grantsupport_auth_failures_total counter\n")
		r.mu.RLock()
		for reason, ptr := range r.authFailuresTotal {
			buf.WriteString(fmt.Sprintf("grantsupport_auth_failures_total{reason=\"%s\"} %d\n", reason, atomic.LoadUint64(ptr)))
		}
		r.mu.RUnlock()
		buf.WriteString("\n")

		// 4. Revocations Total
		buf.WriteString("# HELP grantsupport_revocations_total Total grant and session revocations by scope.\n")
		buf.WriteString("# TYPE grantsupport_revocations_total counter\n")
		r.mu.RLock()
		for scope, ptr := range r.revocationsTotal {
			buf.WriteString(fmt.Sprintf("grantsupport_revocations_total{scope=\"%s\"} %d\n", scope, atomic.LoadUint64(ptr)))
		}
		r.mu.RUnlock()
		buf.WriteString("\n")

		// 5. Rate Limit Exceeded
		buf.WriteString("# HELP grantsupport_rate_limit_exceeded_total Total rate limit rejections by normalized route.\n")
		buf.WriteString("# TYPE grantsupport_rate_limit_exceeded_total counter\n")
		r.mu.RLock()
		for route, ptr := range r.rateLimitTotal {
			buf.WriteString(fmt.Sprintf("grantsupport_rate_limit_exceeded_total{route=\"%s\"} %d\n", route, atomic.LoadUint64(ptr)))
		}
		r.mu.RUnlock()
		buf.WriteString("\n")

		// 6. Webhook Dispatches
		buf.WriteString("# HELP grantsupport_webhook_dispatches_total Total webhook delivery dispatches by outcome status.\n")
		buf.WriteString("# TYPE grantsupport_webhook_dispatches_total counter\n")
		r.mu.RLock()
		for status, ptr := range r.webhookDispatches {
			buf.WriteString(fmt.Sprintf("grantsupport_webhook_dispatches_total{status=\"%s\"} %d\n", status, atomic.LoadUint64(ptr)))
		}
		r.mu.RUnlock()
		buf.WriteString("\n")

		// 7. Active Sessions Gauge
		buf.WriteString("# HELP grantsupport_active_sessions Active delegated support sessions currently authorized.\n")
		buf.WriteString("# TYPE grantsupport_active_sessions gauge\n")
		buf.WriteString(fmt.Sprintf("grantsupport_active_sessions %d\n\n", atomic.LoadInt64(&r.activeSessionsGauge)))

		// 8. DB Pool Gauges
		buf.WriteString("# HELP grantsupport_db_connections_open Total open database connections in pool.\n")
		buf.WriteString("# TYPE grantsupport_db_connections_open gauge\n")
		buf.WriteString(fmt.Sprintf("grantsupport_db_connections_open %d\n\n", atomic.LoadInt64(&r.dbConnectionsOpen)))

		buf.WriteString("# HELP grantsupport_db_connections_in_use Total active database connections in use.\n")
		buf.WriteString("# TYPE grantsupport_db_connections_in_use gauge\n")
		buf.WriteString(fmt.Sprintf("grantsupport_db_connections_in_use %d\n\n", atomic.LoadInt64(&r.dbConnectionsInUse)))

		// 9. HTTP Requests Total
		buf.WriteString("# HELP grantsupport_http_requests_total Total HTTP requests by normalized route and status code.\n")
		buf.WriteString("# TYPE grantsupport_http_requests_total counter\n")
		r.mu.RLock()
		for key, ptr := range r.httpRequestsTotal {
			route, code := parseRouteAndCode(key)
			buf.WriteString(fmt.Sprintf("grantsupport_http_requests_total{route=\"%s\",status_code=\"%s\"} %d\n", route, code, atomic.LoadUint64(ptr)))
		}
		r.mu.RUnlock()
		buf.WriteString("\n")

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}
}

func parseRouteAndCode(key string) (string, string) {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}
	return key, "200"
}
