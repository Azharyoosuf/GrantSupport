# GrantSupport Operational Observability & Metrics

GrantSupport provides a native, zero-dependency, pull-based Prometheus metrics exposition endpoint at `GET /metrics`.

---

## 1. Core Principles & Privacy Fortress

* **Zero External Telemetry**: GrantSupport will **never** initiate outbound push telemetry, usage tracking, heartbeat pings, or phone-home requests.
* **Low-Cardinality Design**: All metric labels are strictly bounded, static string enums.
* **Absolute Privacy**: Metric labels **NEVER** contain tenant UUIDs, user IDs, support agent IDs, token hashes, raw URLs, dynamic scope strings, or unredacted error messages.

---

## 2. Metric Inventory

### Counters

| Metric Name | Labels | Description |
| :--- | :--- | :--- |
| `grantsupport_grants_created_total` | *None* | Total number of single-use support access grants generated. |
| `grantsupport_logins_total` | `status="success\|failure"` | Total support agent grant redemptions by outcome. |
| `grantsupport_auth_failures_total` | `reason="token_expired\|token_revoked\|invalid_signature\|invalid_kid\|missing_claims\|insufficient_role"` | Total authentication rejections categorized by static reason. |
| `grantsupport_revocations_total` | `scope="tenant\|agent\|session"` | Total access revocations categorized by revocation boundary. |
| `grantsupport_rate_limit_exceeded_total` | `route="/api/v1/auth/support/login\|/api/v1/auth/support/grant\|/api/v1/auth/support/revoke"` | Total rate-limiting 429 rejections by normalized route pattern. |
| `grantsupport_webhook_dispatches_total` | `status="delivered\|retrying\|dead_letter\|dropped_queue_full"` | Total webhook delivery outcomes. |
| `grantsupport_http_requests_total` | `route="<route_pattern>", status_code="<code>"` | Total HTTP requests handled by normalized route pattern and status. |

### Histograms

| Metric Name | Labels | Description |
| :--- | :--- | :--- |
| `grantsupport_http_request_duration_seconds` | `route="<route_pattern>", le="<bucket>"` | HTTP request latency distribution in seconds by normalized route pattern. |

### Gauges

| Metric Name | Labels | Description |
| :--- | :--- | :--- |
| `grantsupport_active_sessions` | *None* | Current number of active, redeemed support sessions (refreshed on scrape). |
| `grantsupport_db_connections_open` | *None* | Current open database connection pool count (refreshed on scrape). |
| `grantsupport_db_connections_in_use` | *None* | Current active database connections executing queries (refreshed on scrape). |

---

## 3. Securing `GET /metrics`

`GET /metrics` is **public (unauthenticated) by default** so standard Prometheus scrapers can pull metrics without provisioning short-lived RS256 tenant JWTs. Although metric labels never contain PII, UUIDs, or client IPs, operational request counts and error rates should not be exposed to the public internet.

Protect `GET /metrics` in production using one of the following patterns:

1. **Reverse Proxy / Ingress ACLs (Standalone Server)**: Restrict `/metrics` at your reverse proxy (nginx, Traefik, Envoy, or cloud load balancer) to internal monitoring subnet CIDRs or require HTTP Basic Auth / mTLS:
   ```nginx
   location = /metrics {
       allow 10.0.0.0/8;
       allow 172.16.0.0/12;
       deny all;
       proxy_pass http://grantsupport:8080/metrics;
   }
   ```
2. **Middleware Wrapper (Embedded Go Library)**: When mounting `engine.HTTPHandler()` inside a host Go application, wrap or intercept `/metrics` with an internal network CIDR check or scraper bearer-token middleware before delegating to `engine.HTTPHandler()`.

---

## 4. Prometheus Scrape Configuration

Add the following scrape job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'grantsupport'
    scrape_interval: 15s
    scrape_timeout: 5s
    static_configs:
      - targets: ['grantsupport-service:8080']
    metrics_path: '/metrics'
```

---

## 5. Recommended Alerting Rules

```yaml
groups:
  - name: grantsupport_alerts
    rules:
      - alert: HighAuthenticationFailures
        expr: rate(grantsupport_auth_failures_total[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Elevated authentication failures on GrantSupport"
          description: "GrantSupport is experiencing > 5 auth rejections/sec over the last 5 minutes."

      - alert: WebhookQueueOverflow
        expr: increase(grantsupport_webhook_dispatches_total{status="dropped_queue_full"}[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "GrantSupport Webhook Queue Overflow"
          description: "The in-memory webhook retry queue is full; downstream receiver may be unreachable."
```
