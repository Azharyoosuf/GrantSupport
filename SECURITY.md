# Security Policy

## Supported Versions

Only the latest release of GrantSupport receives active security updates.

| Version       | Supported          |
| :---          | :---:              |
| v0.1.0-beta.3 | :white_check_mark: |
| < 0.1.0-beta.3| :x:                |

---

## Core Security Invariants

GrantSupport is architected around non-negotiable security principles:

1. **Multi-Tenant Isolation**: Every database query, mutation, and cryptographic verification strictly enforces `institution_id` filtering. Cross-tenant access is impossible.
2. **Self-Approval Prohibition**: Requesters are mathematically forbidden from approving their own access requests (`SELF_APPROVAL_FORBIDDEN`).
3. **Zero Raw Token Persistence**: Single-use support tokens are returned exactly once to the authorized caller and stored strictly as SHA-256 hashes in `gs_support_grants`. Raw tokens are never written to disk, audit logs, or webhooks.
4. **Fail-Closed Design**: Unknown signing key IDs (`kid`), expired grants, missing revocation stores, or tampered signatures result in immediate, fail-closed rejection.
5. **Cryptographic Tamper-Evident Ledger**: All lifecycle state transitions write append-only, SHA-256 chained audit entries.

---

## Reporting a Vulnerability

If you discover a security vulnerability within GrantSupport, please **do NOT report it publicly on GitHub issues**.

Instead, please responsibly disclose it via email or GitHub Private Vulnerability Reporting:

- **Email**: `security@grantsupport.io` (or repository maintainer)
- **GitHub**: Use the "Report a vulnerability" button under the **Security** tab of the repository.

### What to Include

Please provide:
1. A description of the vulnerability and its potential impact.
2. Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
3. Any affected configurations or versions.

### Response Timeline

- **Initial Response**: Within 48 hours of receipt.
- **Triage & Assessment**: Within 5 business days.
- **Patch & Advisory Release**: Once a fix is verified and ready for deployment.
