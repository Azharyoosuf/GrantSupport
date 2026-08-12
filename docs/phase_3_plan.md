# Phase 3 Implementation Plan: Containerization & Docker Deployment

## 📌 Problem & Context
1. **Empty `docker/` Directory**: No multi-stage Dockerfile or compose manifests.
2. **Missing `.env.example`**: Operators have no documented list of required/optional env vars. *(Fixed in Phase 1.)*
3. **Full `migrations/` mount exposes MySQL script to Postgres** (F-3-A): The entire `migrations/` folder cannot be mounted into `docker-entrypoint-initdb.d`; only the dialect-specific subdirectory may be mounted.
4. **Hardcoded `MASTER_ENCRYPTION_KEY`** (finding #2/#38): The docker-compose.yml example must NOT hard-code a real key; it must reference an env var.

> **CGO note**: Phase 2 replaces `mattn/go-sqlite3` with `modernc.org/sqlite` (pure Go). The Dockerfile continues to build with `CGO_ENABLED=0` and a plain Alpine image. No gcc layer is required.

---

## 🛠️ Detailed Proposed Code Changes

### Component 1: `docker/Dockerfile`

#### [NEW] [Dockerfile](file:///d:/Hostel_management/GrantSupport/docker/Dockerfile)

```dockerfile
# Stage 1: Build Binary
# P6 fix: golang:1.25-alpine does not exist (Go 1.25 is unreleased). Use 1.23-alpine.
# Update this to match the `go` directive in go.mod when upgrading.
FROM golang:1.23-alpine AS builder

WORKDIR /build

# ca-certificates needed for outbound TLS (webhooks, KMS calls).
RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: pure-Go build (compatible with modernc.org/sqlite; see Phase 2 for driver choice).
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/grantsupport ./cmd/server

# Stage 2: Minimal Hardened Runtime Image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Non-root unprivileged user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app/grantsupport /app/grantsupport

USER appuser:appgroup

EXPOSE 8085

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8085/health || exit 1

ENTRYPOINT ["/app/grantsupport"]
```

---

### Component 2: `docker/docker-compose.yml`

#### [NEW] [docker-compose.yml](file:///d:/Hostel_management/GrantSupport/docker/docker-compose.yml)

> **Fix (F-3-A)**: Mount only `../migrations/postgres` into `docker-entrypoint-initdb.d`. The MySQL scripts live in `../migrations/mysql` and are never seen by Postgres.
>
> **Fix (finding #38)**: `MASTER_ENCRYPTION_KEY` uses `${MASTER_ENCRYPTION_KEY}` variable substitution instead of a hardcoded value. Copy `.env.example` to `.env` and set this before running.

```yaml
version: '3.8'

services:
  grantsupport-core:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    container_name: grantsupport-core
    ports:
      - "8085:8085"
    environment:
      - PORT=8085
      - GO_ENV=production
      - DATABASE_DIALECT=postgres
      - DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/grantsupport_db?sslmode=disable
      - VALKEY_CACHE_URL=redis://valkey:6379
      - ENCRYPTION_PROVIDER=LOCAL
      # Never hard-code MASTER_ENCRYPTION_KEY. Set it in your .env file or secrets manager.
      - MASTER_ENCRYPTION_KEY=${MASTER_ENCRYPTION_KEY}
      - JWT_PRIVATE_KEY=${JWT_PRIVATE_KEY}
      - JWT_PUBLIC_KEY=${JWT_PUBLIC_KEY}
      - LICENSE_KEY=${LICENSE_KEY}
      - LICENSE_PUBLIC_KEY=${LICENSE_PUBLIC_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    container_name: grantsupport-postgres
    environment:
      POSTGRES_DB: grantsupport_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5434:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      # Mount ONLY the postgres-specific subdirectory (F-3-A fix).
      # This prevents Postgres from trying to run MySQL trigger scripts.
      - ../migrations/postgres:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d grantsupport_db"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  valkey:
    image: valkey/valkey:7.2-alpine
    container_name: grantsupport-valkey
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "valkey-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  pgdata:
```

---

### Component 3: Migration Execution for Existing Deployments (finding #30)

> **Known gap addressed**: `docker-entrypoint-initdb.d` only runs scripts on a **fresh** database volume. It does not execute scripts when upgrading an existing deployment. The following is the documented upgrade procedure:

#### Upgrade procedure (run via `golang-migrate` — recommended for all environments):

```bash
# Install golang-migrate once (if not already present):
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Apply ALL pending migrations in order (000001, 000002, 000003, ...):
migrate -path migrations/postgres -database "${DATABASE_URL}" up
```

For MySQL deployments, use the `mysql` tag and `migrations/mysql/` path:
```bash
migrate -path migrations/mysql -database "${DATABASE_URL}" up
```

> **P8 fix**: The previous example ran only `000002_add_immutability_triggers.sql` via a manual `psql` command. This was wrong for two reasons:
> 1. It silently skipped `000001` (required for a fresh non-Docker deployment).
> 2. It becomes stale whenever a new migration file is added (e.g., `000003_add_hash_chain_check.sql` from Phase 5).
>
> `migrate ... up` applies all pending migrations in numeric order and is safe to re-run (already-applied migrations are skipped). This is the only supported upgrade mechanism.


---

## 🧪 Verification Plan

### Container Build & Orchestration
```bash
cp .env.example .env     # fill in all REQUIRED values
docker compose -f docker/docker-compose.yml up --build -d
docker ps --filter "name=grantsupport"
curl -i http://localhost:8085/health
```
Expect `200 OK` with `{"status":"UP","service":"GrantSupport Engine"}`.

### Confirm No MySQL Script Executed by Postgres
```bash
docker logs grantsupport-postgres 2>&1 | grep -i "DELIMITER"
```
Expect: zero matches (MySQL script is not in the mounted postgres subdirectory).
