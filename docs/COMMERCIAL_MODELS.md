# Source-Available Architecture & Deployment Principles

GrantSupport is a source-available (BSL 1.1) delegated support-access authentication and cryptographic audit engine.

---

## 1. Architectural Principles & Guarantees

1. **Zero Runtime Enforcement / License Servers**: No license validation servers, no seat limits, no human vs AI agent caps, and no remote activation checks.
2. **Zero Phone-Home / Telemetry**: No external heartbeat pings, no machine fingerprinting, and no mandatory external cloud services.
3. **Customer Data Ownership**: All audit ledgers, support grants, and tenant access records remain entirely within the customer's self-hosted infrastructure.
4. **Transparent Source Availability**: Licensed under the Business Source License 1.1 (BSL 1.1), converting automatically to Apache 2.0 on August 14, 2030.

---

## 2. Deployment Models

### Minimal Standalone (PostgreSQL / MySQL / MariaDB / SQLite)
Deploy GrantSupport alongside your database with zero external infrastructure:
```bash
docker run -d \
  -e DATABASE_URL="postgres://user:pass@db:5432/grantsupport?sslmode=disable" \
  -e JWT_PRIVATE_KEY="$(cat jwt_rsa.key)" \
  -e JWT_PUBLIC_KEY="$(cat jwt_rsa.pub)" \
  -p 8085:8085 \
  grantsupport:latest
```

### High-Scale Distributed (Database + Optional Valkey/Redis)
For high-traffic multi-container deployments, optionally attach Valkey/Redis for accelerated distributed locking, rate limiting, and token revocation:
```bash
docker run -d \
  -e DATABASE_URL="postgres://user:pass@db:5432/grantsupport?sslmode=disable" \
  -e VALKEY_CACHE_URL="redis://valkey:6379" \
  -p 8085:8085 \
  grantsupport:latest
```

### Embedded Go Library
Import GrantSupport directly into your Go application and reuse your existing `*sql.DB`, `*ent.Client`, or `*pgxpool.Pool` without running a separate service container.
