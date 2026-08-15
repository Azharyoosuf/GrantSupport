# Zero-Downtime RSA Key Rotation Runbook

GrantSupport uses asymmetric RS256 signing for support agent JWTs. Key ID (`kid`) tracking enables zero-downtime key rotation across downstream API gateways and microservices.

---

## 1. Key Selection & Verification Rules

1. **Strict Key Selection**: When a token carries a `kid` header, GrantSupport **strictly** looks up that Key ID in its trusted public keys. If the `kid` is unknown or untrusted, verification **fails closed immediately** with HTTP 401 Problem Details `INVALID_TOKEN_SIGNATURE`. GrantSupport **never** falls back to trying the primary key on an unknown `kid`.
2. **Legacy Token Compatibility**: Tokens issued before `kid` support was enabled omit the `kid` header. These tokens are verified against the configured legacy verification key.

---

## 2. Zero-Downtime Rotation Lifecycle

```
[Phase 1: Normal State]
  Primary Signing Key: Key-A (kid: 2026-v1)
  JWKS Published: [Key-A]

[Phase 2: Key Promotion & Rollover Window]
  Primary Signing Key: Key-B (kid: 2026-v2) [signs new tokens]
  Transitional Keys:  Key-A (kid: 2026-v1) [verifies active tokens]
  JWKS Published: [Key-B, Key-A]

[Phase 3: Grace Period Expiration]
  Wait max support session duration (e.g., 24 hours) for Key-A tokens to expire.
  Remove Key-A from transitional verification set.

[Phase 4: New Normal State]
  Primary Signing Key: Key-B (kid: 2026-v2)
  JWKS Published: [Key-B]
```

---

## 3. Operational Step-by-Step Guide

### Step 1: Generate New Keypair
```bash
# Generate 2048-bit RSA Private Key
openssl genpkey -algorithm RSA -out jwt_private_v2.pem -pkeyopt rsa_keygen_bits:2048

# Extract Public Key
openssl rsa -pubout -in jwt_private_v2.pem -out jwt_public_v2.pem
```

### Step 2: Configure Transitional Key Rollover in Environment / Options
Deploy the new release configuring:
* `JWT_KEY_ID="2026-v2"` (New active primary)
* `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` pointing to v2 keys.
* Programmatically register Key-A public key via `keyManager.AddTransitionalPublicKey("2026-v1", pubKeyA)`.

### Step 3: Verify JWKS Exposition
Confirm both keys are advertised at `GET /.well-known/jwks.json`:
```json
{
  "keys": [
    {
      "kid": "2026-v2",
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    },
    {
      "kid": "2026-v1",
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Step 4: Decommission Expired Transitional Key
Once all sessions issued under Key-A have passed their 24-hour expiration window:
```go
keyManager.RemoveTransitionalPublicKey("2026-v1")
```
Key-A is now removed from `/.well-known/jwks.json` and any subsequent requests with `kid: 2026-v1` are rejected.
