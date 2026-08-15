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
| `grantsupport_rate_limit_exceeded_total` | `route="auth_login\|auth_grant\|auth_revoke"` | Total rate-limiting 429 rejections by normalized route. |
| `grantsupport_webhook_dispatches_total` | `status="delivered\|retrying\|dead_letter\|dropped_queue_full"` | Total webhook delivery outcomes. |
| `grantsupport_http_requests_total` | `route="<normalized_route>", status_code="<code>"` | Total HTTP requests handled by normalized route and status. |

### Gauges

| Metric Name | Labels | Description |
| :--- | :--- | :--- |
| `grantsupport_active_sessions` | *None* | Current number of active, redeemed support sessions. |
| `grantsupport_db_connections_open` | *None* | Current open database connection pool count. |
| `grantsupport_db_connections_in_use` | *None* | Current active database connections executing queries. |

---

## 3. Prometheus Scrape Configuration

Add the following scrape job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'grantsupport'
    scrape_interval: 15s
    scrape_timeout: 5s
    static_configs:
      - targets: ['grantsupport-service:8085']
    metrics_path: '/metrics'
```

---

## 4. Recommended Alerting Rules

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
