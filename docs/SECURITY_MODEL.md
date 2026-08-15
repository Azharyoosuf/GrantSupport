# GrantSupport Security Model & Threat Specification

This document provides a formal definition of GrantSupport's security goals, threat model, trust boundaries, cryptographic invariants, and security non-goals.

---

## 1. Security Goals

GrantSupport is designed to provide:
1. **Delegation Security**: Enable administrators to delegate time-bounded, single-use access to vendor support personnel without revealing permanent administrative passwords.
2. **Dynamic Session Binding**: Ensure support session JWTs cannot outlive the duration explicitly authorized at grant creation time.
3. **Atomic Consumption**: Ensure a support delegation token can be redeemed exactly once, even under high-concurrency race conditions.
4. **Instant Revocation**: Allow administrators to immediately terminate active support sessions across distributed nodes.
5. **Tamper-Evident Auditability**: Maintain an append-only, chronologically chained cryptographic audit log of all grant lifecycle operations.
6. **Zero-Trust Token Exposure**: Ensure raw support tokens are never persisted in plaintext, never logged, and never reflected in error messages.

---

## 2. Cryptographic Invariants

### 2.1 Raw Token Generation & Storage
* **Entropy**: Generated using `crypto/rand` reading 32 cryptographically secure random bytes (256 bits of entropy).
* **Format**: `{institution_id}_{hex_encoded_32_bytes}`.
* **Storage**: Only the SHA-256 hash (`token_hash`) is stored in the `gs_support_grants` table. The raw token is returned once upon creation and discarded from server memory.

### 2.2 Session JWT Signing
* **Algorithm**: Asymmetric RS256 (RSA Signature with SHA-256).
* **Key Pair**: 2048-bit RSA private key (`JWT_PRIVATE_KEY`) for signing; public key (`JWT_PUBLIC_KEY`) for verification.
* **Claims Structure**:
  * `institution_id`: Explicit UUID identifying the authorized customer tenant.
  * `user_id`: UUID of the support agent claiming the grant.
  * `role`: Fixed to `SUPPORT_AGENT`.
  * `scope`: Permission scope string specified at grant creation (e.g. `BILLING_ONLY`).
  * `token_version`: Monotonic integer used for revocation tracking.
  * `exp`: Unix timestamp strictly bounded to `grant.ExpiresAt`.
  * `iat`: Issue timestamp.

### 2.3 Audit Hash Chaining
* **Algorithm**: SHA-256.
* **Chaining Formula**:
  $$\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{EventData}_n)$$
* **Verification**: `VerifyAuditChain(ctx, institutionID)` traverses the audit events in ascending chronological order, recomputing the SHA-256 hash chain and confirming no records were deleted, inserted, or altered.

---

## 3. Threat Analysis & Mitigations

| Threat Vector | Attack Scenario | Mitigation in GrantSupport |
| :--- | :--- | :--- |
| **Token Interception at Rest** | Attacker reads database backup or table rows. | Only SHA-256 token hashes are stored in the database. Raw tokens cannot be reverse-engineered from hashes. |
| **Concurrent Race Redemption** | Attacker intercepts a token and races the legitimate agent to claim it. | Atomic SQL conditional update (`WHERE id = ? AND is_used = false`). Exactly one claim succeeds; all subsequent attempts fail with `ErrGrantAlreadyUsed`. |
| **Session Lingering** | Support agent attempts to use credentials days after maintenance is complete. | Token expiration is bound to grant duration (max 1440 mins). After expiration, JWT signatures fail automatically. |
| **Malicious Network Access** | Attacker obtains token and attempts redemption from unauthorized IP. | `whitelistedIps` enforcement validates client IP against authorized CIDR/IP list before granting access. |
| **Revocation Bypass** | Revoked agent attempts requests with an unexpired JWT. | `NewAuthMiddleware` verifies the JWT's `token_version` against the `RevocationStore`. Incremented version immediately rejects requests. |
| **Revocation Store Outage Bypass** | Attacker causes Redis outage hoping revocation checks fail open. | Fail-closed design: If the `RevocationStore` cannot be queried, the middleware rejects requests with HTTP 503 `REVOCATION_CHECK_UNAVAILABLE`. |
| **Audit Log Tampering** | Malicious DB administrator deletes or modifies an audit row to hide unauthorized access. | Sequential SHA-256 hash chain breaks. `VerifyAuditChain` immediately identifies the broken link. |
| **Error Information Disclosure** | Attacker sends malformed payloads to extract database schemas from error traces. | Problem Details (RFC 9457) error formatting masks all internal driver errors and returns generic sanitized client descriptions. |

---

## 4. Trust Boundaries & Responsibilities

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   HOST APPLICATION                                     │
│                                                                                        │
│   [Handles]                                                                            │
│   - Domain business logic and data access rules                                        │
│   - Inspection and enforcement of JWT 'scope' claim (e.g. BILLING_ONLY)                │
│   - Physical verification of vendor support agent identity                             │
│   - Customer administrator authentication prior to calling /grant or /revoke           │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Calls via HTTP or in-process Go
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                     GRANTSUPPORT                                       │
│                                                                                        │
│   [Handles]                                                                            │
│   - Generation, hashing, single-use CAS redemption of support tokens                   │
│   - Dynamic duration matching (session exp == grant exp)                               │
│   - RS256 JWT issuance and active session revocation verification                      │
│   - IP whitelist validation                                                            │
│   - Cryptographic SHA-256 append-only audit trail logging                              │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              STORAGE & COORDINATION LAYER                              │
│                                                                                        │
│   - PostgreSQL / MySQL / MariaDB / SQLite (Isolated persistence)                       │
│   - Valkey 7.2 / Redis 7 (Distributed locking & token version cache)                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Security Non-Goals

GrantSupport explicitly does **NOT** provide:
1. **Application-Level Authorization**: GrantSupport embeds the requested `scope` into the JWT, but does not know your application's domain tables or API endpoints. The host application must enforce its own authorization rules.
2. **Network Firewalls / DDoS Mitigation**: While GrantSupport provides an IP rate limiter on `/login`, broad volumetric DDoS mitigation must be handled by upstream reverse proxies or WAFs (e.g. Cloudflare, AWS ALB).
3. **Public Browser CORS API**: GrantSupport is an internal infrastructure service and does not attach permissive CORS headers.
4. **Agent Background Checks**: GrantSupport relies on the host application to verify the legitimacy of the `agentId` UUID passed during login.
