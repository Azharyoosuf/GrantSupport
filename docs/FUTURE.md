# GrantSupport — Future Roadmap & Experimental Architecture

This document tracks reference implementations, experimental prototypes, and architectural capabilities designed for future enterprise and multi-region extensions of GrantSupport.

---

## 1. Merkle Tree Audit Notarization

### Context
GrantSupport currently verifies audit trails using **sequential cryptographic hash-chaining** (`gs_audit_events.hash_chain` with SHA-256), where each event cryptographically binds to the previous event's hash in chronological sequence, tamper-evident against edits to individual event records. Someone with database write access could recompute the chain, so external checkpointing of the chain head is planned, not yet implemented.

### Future Capability
The `CalculateMerkleRoot` and `GenerateMerkleProof` utilities provide binary Merkle tree aggregation and cryptographic inclusion proofs.

* **Use Case**: Batching audit log events into Merkle roots for periodic external anchoring (e.g. public ledger notarization, decentralized timestamping, or cross-datacenter state proofs).
* **Current Status**: Removed from the active codebase (`pkg/security/experimental/merkle.go` had no production callers); recoverable from git history when external notarization is scheduled.

---

## 2. Granular Field-Level Envelope Encryption

### Context
GrantSupport stores sensitive support access tokens as cryptographic SHA-256 hashes at rest, and support sessions are cryptographically signed using RS256 asymmetric keys.

### Future Capability
The `LocalEncryptionService` (HKDF AES-256-GCM) and `KMSEncryptionService` (AWS KMS `GenerateDataKey` envelope encryption) provide per-tenant isolated field-level encryption.

* **Use Case**: Transparent column-level encryption for customer PII payloads when integrated into host platforms requiring per-tenant encryption key isolation.
* **Current Status**: Removed from the active codebase (`pkg/security/experimental/encryption.go` had no production callers and pulled in unused AWS SDK and `golang.org/x/crypto` dependencies); recoverable from git history if per-tenant field encryption is added.
