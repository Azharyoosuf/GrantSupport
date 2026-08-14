# Technical Architecture & Security Specification

This document details the architectural design, cryptographic primitives, threat model, database portability, and audit verification guarantees of **GrantSupport**.

---

## 1. System Architecture: Standalone vs. Embedded Engine

GrantSupport is architectured to operate in two distinct modes without architectural compromise:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 STANDALONE MICROSERVICE                                │
│                                                                                        │
│   HTTP Client (Python, Node, Java, Go, C#, Rust) ──► Chi Router (:8085)                │
│                                                            │                           │
│                                                            ▼                           │
│                                                SupportGrantController                  │
│                                                            │                           │
│                                                            ▼                           │
│                                                   GrantSupportService                  │
│                                                      │             │                   │
│                              ┌───────────────────────┘             └─────────┐         │
│                              ▼                                               ▼         │
│                    SupportGrantRepository                         SecurityAuditRepo   │
│                              │                                               │         │
│                              ▼                                               ▼         │
│                     Ent ORM / Database Pool (PostgreSQL, MySQL, MariaDB, SQLite)       │
└────────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              EMBEDDED GO IN-PROCESS ENGINE                             │
│                                                                                        │
│   Host Go Application ──► grantsupport.NewEngine(WithDB(db, "postgres"))               │
│                                  │                                                     │
│        ┌─────────────────────────┴─────────────────────────┐                           │
│        ▼                                                   ▼                           │
│   Direct Go Engine API (In-Process)              engine.HTTPHandler()                  │
│   engine.CreateSupportGrant(...)                 Mounted under host router /api/v1/... │
│   engine.SupportLogin(...)                                                             │
│   engine.VerifyAuditChain(...)                                                         │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Strategic Architectural Principles:
1. **Zero External Dependencies Required**: Operates with a single SQL database:
   - **PostgreSQL**: Reference and primary production database.
   - **MySQL (8.0+) & MariaDB (10.5+)**: Supported enterprise relational database alternatives.
   - **SQLite**: Supported for single-process embedded applications, local development, and test suites (not distributed across multi-container replicas).
2. **Valkey & Redis Officially Supported**: Distributed caching and locking officially support **Valkey** and **Redis** (other Redis-protocol-compatible implementations may work but are not officially verified or supported). System operates fully without Redis/Valkey by falling back to SQL database tables or in-memory stores.
3. **Zero Connection Leakage**: Reuses caller-managed `*sql.DB`, `*ent.Client`, or `*pgxpool.Pool` connection pools without creating secondary pools.
4. **Zero Telemetry / Zero Phone-Home**: Contains no license servers, no heartbeat pings, no seat enforcement counters, and no remote telemetry.
5. **Tenant Isolation by Construction**: Every repository query enforces strict `institution_id` scoping.

---

## 2. Delegation Token Lifecycle & Security Control Flow

GrantSupport implements **Delegated Support Access with Single-Use Ephemeral Tokens**:

```
[Customer Admin] ──1. POST /api/v1/auth/support/grant (duration: 60m, scope: BILLING_ONLY)──► [GrantSupport]
                                                                                                  │
                                                                                    2. crypto/rand 32 bytes
                                                                                    3. rawToken = {instID}_{rand}
                                                                                    4. Store SHA-256(rawToken)
                                                                                    5. Log SUPPORT_ACCESS_GRANTED
                                                                                    6. Dispatch webhook (grant.created)
                                                                                                  │
[Support Agent] ◄──7. Returns rawToken (only returned once, never persisted)─────────────────────┘
       │
       ├──8. POST /api/v1/auth/support/login (rawToken, agentId)───────────────────► [GrantSupport]
                                                                                                  │
                                                                                    9. Verify SHA-256(rawToken)
                                                                                    10. Check ExpiresAt > NOW()
                                                                                    11. Atomic CAS UPDATE (is_used=true, used_by_id=agentID)
                                                                                    12. Issue RS256 JWT (ExpiresAt = Grant.ExpiresAt)
                                                                                    13. Log SUPPORT_ACCESS_LOGGED_IN
                                                                                    14. Dispatch webhook (grant.claimed)
                                                                                                  │
[Support Agent] ◄──15. Returns RS256 JWT (scoped to InstitutionID, Duration & Role: SUPPORT_AGENT)─┘
```

### Security Guarantees:
* **High Entropy**: 256 bits of cryptographic entropy (`crypto/rand`) per token.
* **Hashed at Rest**: Only the SHA-256 hash of the token is stored in the database. Raw tokens are never persisted.
* **Atomic Single-Use Consumption**: Token redemption uses an atomic conditional predicate:
  ```sql
  UPDATE gs_support_grants
  SET is_used = true, used_by_id = ?, used_at = CURRENT_TIMESTAMP
  WHERE id = ? AND is_used = false;
  ```
  If concurrent requests attempt to claim the same grant token, exactly one succeeds and all other requests fail (`ErrGrantAlreadyUsed`).
* **Time-Bound Expiration & Dynamic Session Lifetime**: Grants carry strict TTLs (1 to 1440 minutes). The issued `SUPPORT_AGENT` JWT is dynamically bound to the exact grant expiration timestamp (`session expiration <= grant expiration`).
* **Dual Grant and Active Session Revocation**:
  - `POST /api/v1/auth/support/revoke` immediately invalidates all **unredeemed support grants** for the tenant AND revokes all currently active `SUPPORT_AGENT` JWT sessions by incrementing the tenant's agent token version in the `RevocationStore`.
  - `POST /api/v1/auth/support/logout` allows a support agent to invalidate their active JWT session immediately upon completing maintenance.

---

## 3. Cryptographically Chained, Tamper-Evident Audit Ledger

Every support access lifecycle event is recorded in a cryptographically linked, append-only audit ledger:

### 3.1 SHA-256 Hash Chaining Formula
For every `AuditEvent` entry $E_n$:
$$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} \parallel \text{InstitutionID} \parallel \text{ActorID} \parallel \text{EventType} \parallel \text{SanitizedDescription} \parallel \text{TimestampNanos})$$

```
[Genesis Hash: 0000000000000000000000000000000000000000000000000000000000000000]
                                   │
                                   ▼
[Event 1: SUPPORT_ACCESS_GRANTED] ──► Hash_1 = SHA256(Genesis || InstID || AdminID || ...)
                                   │
                                   ▼
[Event 2: SUPPORT_ACCESS_LOGGED_IN] ─► Hash_2 = SHA256(Hash_1 || InstID || AgentID || ...)
                                   │
                                   ▼
[Event 3: SUPPORT_ACCESS_REVOKED] ──► Hash_3 = SHA256(Hash_2 || InstID || AdminID || ...)
```

### 3.2 Audit Serialization & Tamper Detection
* **Per-Institution In-Process Mutex Striping**: Serializes concurrent audit writes within a process to eliminate hash-chain forks without creating cross-tenant lock contention.
* **Distributed Cross-Process Locking**: Attaches SQL or Redis distributed locks when running across multiple container replicas.
* **Tamper Verification**: `VerifyAuditChain(ctx, institutionID)` re-computes every cryptographic hash link from genesis to tail. If any record was modified, deleted, or inserted out of sequence, verification fails and identifies the exact event ID of the violation.

---

## 4. Automated PII & Credential Sanitization

Before writing to the audit ledger, all textual descriptions and event metadata maps pass through `security.SanitizeAuditText()` and `security.SanitizeAuditMap()`. The sanitizer automatically redacts:
* **Bearer Tokens & Passwords**: `bearer eyJ...` ➔ `Bearer [REDACTED_TOKEN]`
* **Credit Cards (PAN)**: 13–19 digit sequences ➔ `[REDACTED_CARD]`
* **Email Addresses**: RFC 5322 matching patterns ➔ `[REDACTED_EMAIL]`
* **Phone Numbers**: E.164 and international formats ➔ `[REDACTED_PHONE]`

---

## 5. Capability Stores & Failure Policies

GrantSupport provides pluggable capability adapters with explicit failure modes:

| Capability | Valkey/Redis Adapter | SQL Adapter | In-Memory Fallback | Failure Policy |
| :--- | :--- | :--- | :--- | :--- |
| **Distributed Lock** | `RedisLockStore` (SETNX + Lua) | `SQLLockStore` (`gs_locks`) | `MemoryLockStore` (Mutex) | Rejects on timeout / contention |
| **Replay Prevention** | `RedisReplayStore` (EXPIRE) | `SQLReplayStore` (`gs_replays`) | `MemoryReplayStore` (TTL Map) | **Fail-closed** (Rejects replay) |
| **Token Revocation** | `RedisRevocationStore` (Version) | `SQLRevocationStore` (`gs_revocations`) | — | **Fail-closed** (503 on store error) |
| **Rate Limiter** | `RedisRateLimiter` (INCR) | — | `MemoryRateLimiter` (Token Bucket) | **Fail-closed** (503 on store error) |

---

## 6. Optional Encryption & Key Management

* **Local Encryption**: HKDF-derived per-tenant keys using SHA-256 master key + AES-256-GCM authenticated encryption.
* **AWS KMS Envelope Encryption**: Optional AWS KMS provider using `GenerateDataKey` with tenant-scoped encryption contexts (`institutionId`).
* *Scope*: Encryption infrastructure is provided as a utility for application-level data protection; it is not automatically applied to every database field.

---

## 7. Threat Model & Countermeasures

| Threat Vector | Attack Scenario | Countermeasure |
| :--- | :--- | :--- |
| **Token Replay Attack** | Attacker intercepts a raw support grant token. | Single-use atomic CAS consumption flag (`is_used = true`) + bounded TTL (max 24h) + SHA-256 storage. |
| **Cross-Tenant Access** | Tenant A attempts to claim or revoke Tenant B's grant. | Strict `institution_id` query scoping + token prefix defense-in-depth verification. |
| **Algorithm Confusion** | Attacker presents an HMAC-signed token to RS256 verifier. | Explicit `SigningMethodRSA` type assertion check in `VerifyJWT()`. |
| **Brute-Force Login** | Attacker attempts random token guessing on `/login`. | IP-based rate limiting (10 req/min/IP) with socket IP extraction and trusted proxy validation. |
| **Audit Ledger Tampering** | Malicious DB operator modifies or deletes access logs. | SHA-256 cryptographic hash-chaining detected by `VerifyAuditChain()`. |
| **Store Failure Bypass** | Redis or SQL store crashes during auth or rate limit check. | **Fail-closed** architecture: returns 503 / 401 rather than allowing unauthenticated or unthrottled access. |

---

## 8. HTTPS, TLS 1.2/1.3 & Transport Security

GrantSupport supports two production deployment architectures for transport security:

### 8.1 Deployment Models
1. **Native TLS Termination**:
   - GrantSupport directly binds to `HTTPS_PORT` (default `8443` or `443`) using standard Go `crypto/tls`.
   - Certificate and private key paths are configured via `TLS_CERT_FILE` and `TLS_KEY_FILE`.
   - If certificate/key files are missing, unreadable, expired, or mismatched, server **fails startup immediately** without insecure fallback.
   - Optional HTTP-to-HTTPS redirect listener runs on `PORT` with HTTP 308 permanent redirect.
2. **Reverse Proxy / Load Balancer Termination**:
   - Upstream reverse proxy (ALB / Cloudflare) terminates TLS and forwards requests to GrantSupport over internal HTTP `PORT`.
   - Client IP and protocol extraction uses a strict `TRUSTED_PROXIES` CIDR whitelist. Untrusted forwarded headers are ignored.

### 8.2 TLS Policy & Cryptographic Defaults
* **Minimum TLS Version**: `tls.VersionTLS12` (TLS 1.0 and TLS 1.1 are rejected).
* **TLS 1.3**: Enabled and negotiated by default with maintained runtime post-quantum hybrid key exchange.
* **Modern Cipher Suites (TLS 1.2)**: ECDHE-ECDSA/RSA with AES-GCM and ChaCha20-Poly1305. All CBC, 3DES, RC4, and static RSA key-exchange ciphers are disabled.
* **HTTP/2**: Supported automatically via ALPN (`h2`, `http/1.1`).
* **Security Headers**: Injects `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY`, and `Strict-Transport-Security` (`max-age=31536000`) on HTTPS connections.
* **Resource Exhaustion Protection**:
  - `ReadHeaderTimeout`: 5 seconds
  - `ReadTimeout`: 15 seconds
  - `WriteTimeout`: 15 seconds
  - `IdleTimeout`: 60 seconds
  - `MaxHeaderBytes`: 1 MB (1 << 20)
