# Technical Architecture & Security Specification

This document details the architectural design, cryptographic primitives, zero-data-liability principles, threat model, and immutability guarantees of **GrantSupport**.

---

## 1. Architectural Philosophy: Control-Plane vs. Data-Plane

GrantSupport separates system responsibilities into two strictly isolated boundaries:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (Your SaaS Infrastructure)                    │
│                                                                                │
│  - Issues signed cryptographic license keys (Ed25519)                          │
│  - Hosts JWKS public keys at /.well-known/jwks.json                            │
│  - Receives light telemetry heartbeats (IP, machine ID, active agent count)    │
│  - ZERO customer data storage (NO user profiles, NO financial ledgers, NO PII) │
└────────────────────────────────────────────────────────────────────────────────┘
                                      ▲
                                      │  Public Key Verification & Heartbeat Ping
                                      ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                   DATA PLANE (Customer Cloud / Docker / VPC)                   │
│                                                                                │
│  - Hosts customer PostgreSQL database and Valkey cache                         │
│  - Stores user profiles, application data, and SupportGrant records             │
│  - Executes local seat enforcement (Human & AI Agent limits)                   │
│  - Maintains append-only SHA-256 hash-chained AuditEvent ledger               │
└────────────────────────────────────────────────────────────────────────────────┘
```

### Strategic Benefits:
1. **Zero Customer PII Exposure**: Your infrastructure never sees or stores customer passwords, emails, tenant data, or application records.
2. **Infinite Horizontal Scale**: Your SaaS server only serves small JSON payloads for JWKS key rotation and daily heartbeats.
3. **SOC 2 & Compliance Ready**: Customers retain total ownership over their audit trail and data residency requirements.

---

## 2. Cryptographic License Verification (Ed25519)

Licenses are issued as base64-encoded, Ed25519-signed JSON Web Tokens (JWL):

### 2.1 License Payload Structure
```json
{
  "lic_id": "lic_994821a_2026",
  "customer_id": "cust_acme_corp",
  "domain_lock": "app.acmecorp.com",
  "max_human_agents": 10,
  "max_ai_agents": 5,
  "tier": "PRO_10",
  "issued_at": 1753880400,
  "expires_at": 1785416400,
  "offline_grace_days": 7
}
```

### 2.2 Local Verification Workflow (Inside Customer's Container)
1. At startup, `license.Manager` reads `LICENSE_KEY` from the environment.
2. The payload and signature are unmarshaled.
3. The signature is verified against your Ed25519 public key (`security.VerifyEd25519Signature(pubKey, payloadBytes, sigBytes)`).
4. If valid, license metadata is stored in Valkey with a TTL matching `expires_at`.

---

## 3. Delegation Token Mechanics & Security Control Flow

GrantSupport implements **Delegated Authorization with Ephemeral Tokens**:

```
[Customer Admin] ──1. POST /auth/support/grant (duration: 60m)──► [GrantSupport Core]
                                                                        │
                                                            2. Generate Raw Token
                                                            3. Save SHA-256(Token) in DB
                                                                        │
[Support Agent] ◄──4. Returns raw Token (inst_99812_a8b9...)──────────┘
       │
       ├──5. POST /auth/support/login (Token)──────────────────► [GrantSupport Core]
                                                                        │
                                                            6. Verify SHA-256(Token)
                                                            7. Check Expiration & Usage
                                                            8. Mark Token Used (One-Time)
                                                            9. Issue 4h SUPPORT_AGENT JWT
                                                                        │
                                                            10. Write AuditEvent Log
```

### Security Properties:
* **One-Time Usage**: Once `SupportLogin` consumes a grant token, `is_used` is set to `true`. Further login attempts with the same token are rejected (`401 SUPPORT_GRANT_INVALID`).
* **Time-Bound Expiration**: Grants automatically expire after the requested duration (e.g. 15m, 1h, 4h).
* **Instant Manual Revocation**: End-users can trigger `POST /auth/support/revoke` at any time, immediately invalidating active tokens and bumping user `TokenVersion`.

---

## 4. Tamper-Evident Ledger & Append-Only Database Triggers

Audit integrity is guaranteed at the database level using PL/pgSQL triggers and SHA-256 hash chains.

### 4.1 SHA-256 Hash Chaining Formula
For every `AuditEvent` and `FinanceLedger` entry $E_n$:
$$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} \parallel \text{EventType} \parallel \text{ActorID} \parallel \text{InstitutionID} \parallel \text{Timestamp})$$

### 4.2 Database Immutability Trigger
```sql
CREATE OR REPLACE FUNCTION prevent_auditevent_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABLE_AUDIT: AuditEvent records are append-only and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_auditevent_update
    BEFORE UPDATE ON "AuditEvent"
    FOR EACH ROW EXECUTE FUNCTION prevent_auditevent_mutation();

CREATE TRIGGER trg_prevent_auditevent_delete
    BEFORE DELETE ON "AuditEvent"
    FOR EACH ROW EXECUTE FUNCTION prevent_auditevent_mutation();
```

---

## 5. Threat Model & Countermeasures

| Threat Vector | Attack Scenario | Countermeasure |
| :--- | :--- | :--- |
| **Token Replay Attack** | Attacker intercepts a raw support grant token. | Single-use consumption flag (`is_used = true`) + short TTL (max 4h) + HTTPS TLS encryption. |
| **Seat Multiplication** | Customer runs 10 containers to bypass a 3-agent limit. | Valkey distributed lock (`Redlock`) + shared PostgreSQL agent seat counter across container replicas. |
| **License Tampering** | Customer modifies `max_human_agents` in the license JSON. | Ed25519 cryptographic signature check fails instantly on payload mutation. |
| **DB Audit Modification** | Malicious DB admin attempts to delete support access logs. | PostgreSQL triggers block `UPDATE` and `DELETE` queries at database driver level. |
