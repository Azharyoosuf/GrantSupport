# GrantSupport — Future Roadmap & Experimental Architecture

This document tracks reference implementations, experimental prototypes, and architectural capabilities designed for future enterprise and multi-region extensions of GrantSupport.

---

## 1. Merkle Tree Audit Notarization (`pkg/security/experimental/merkle.go`)

### Context
GrantSupport currently verifies audit trail immutability using **sequential cryptographic hash-chaining** (`gs_audit_events.hash_chain` with SHA-256), where each event cryptographically binds to the previous event's hash in chronological sequence.

### Future Capability
The `experimental.CalculateMerkleRoot` and `experimental.GenerateMerkleProof` utilities provide binary Merkle tree aggregation and cryptographic inclusion proofs. 

* **Use Case**: Batching audit log events into Merkle roots for periodic external anchoring (e.g. public ledger notarization, decentralized timestamping, or cross-datacenter state proofs).
* **Current Status**: Maintained in `pkg/security/experimental/` as an audited reference implementation.

---

## 2. Granular Field-Level Envelope Encryption (`pkg/security/experimental/encryption.go`)

### Context
GrantSupport stores sensitive support access tokens as cryptographic SHA-256 hashes at rest, and support sessions are cryptographically signed using RS256 asymmetric keys.

### Future Capability
The `experimental.LocalEncryptionService` (HKDF AES-256-GCM) and `experimental.KMSEncryptionService` (AWS KMS `GenerateDataKey` envelope encryption) provide per-tenant isolated field-level encryption.

* **Use Case**: Transparent column-level encryption for customer PII payloads when integrated into host platforms requiring per-tenant encryption key isolation.
* **Current Status**: Maintained in `pkg/security/experimental/` as a modular reference implementation.
