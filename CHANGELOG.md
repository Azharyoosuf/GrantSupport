# Changelog

All notable changes to GrantSupport will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-08-14

### Initial Source-Available Release (BSL 1.1)

#### Core Features
- **Delegated Support Access**: High-entropy, single-use, time-bounded support delegation tokens for multi-tenant systems.
- **Cryptographic Audit Ledger**: Append-only SHA-256 hash-chained security event audit logging with distributed lock serialization.
- **Multi-Database Support**: Native compatibility with PostgreSQL 16, MySQL 8.4, MariaDB 11, and SQLite (pure Go).
- **Valkey / Redis Optionality**: Distributed locking, replay nonces, and session revocation support Valkey with zero-dependency SQL fallbacks.
- **Signed Lifecycle Webhooks**: Outbound HMAC-SHA256 event dispatching with bounded worker concurrency and graceful shutdown draining.
- **Opt-In 5-Layer Machine-to-Machine Security**: Ed25519 asymmetric request signing, timestamp freshness, replay nonce tracking, and IP CIDR binding for custom embedded Go routes.
- **PII & Credential Redaction**: Automated sanitization of credit cards, emails, bearer tokens, passwords, and phone numbers in audit trails.
