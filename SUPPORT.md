# Support Guidelines

Thank you for using GrantSupport. Please review the channels below to find assistance, ask questions, or report problems.

---

## 1. Usage, Configuration & Integration Questions

For general questions on how to configure, deploy, or integrate GrantSupport with your applications:

* **GitHub Discussions (Q&A)**: Use the [GitHub Discussions Q&A Category](https://github.com/azharyoosuf/grantsupport/discussions) to ask questions, share architecture patterns, and seek guidance from the community.
* **Documentation & Runbooks**:
  * [Developer Integration Guide](docs/INTEGRATION_GUIDE.md) — HTTP API, Go embedding, Node.js, and Python examples.
  * [Architecture Specification](docs/ARCHITECTURE.md) — Internal design, transaction boundaries, and capability adapters.
  * [Observability & Metrics](docs/OBSERVABILITY.md) — Prometheus scrapers, health probes, and alert metrics.
  * [Key Rotation Guide](docs/KEY_ROTATION.md) — Zero-downtime RSA key management.

---

## 2. Bug Reports & Feature Requests

* **Actionable Bugs**: If you encounter unexpected behavior, failed assertions, or driver errors, please open a [GitHub Issue](https://github.com/azharyoosuf/grantsupport/issues) using the **Bug Report** template with full reproduction steps.
* **Feature Suggestions**: To propose architectural enhancements or additional database adapters, submit a **Feature Request** on GitHub Issues.

---

## 3. Security Vulnerabilities (CRITICAL)

> [!CAUTION]
> **Do NOT report security vulnerabilities, authentication bypasses, or cryptographic flaws publicly in GitHub Issues or Discussions.**

If you discover a security vulnerability:
* Consult the [Security Policy](SECURITY.md) for responsible disclosure instructions.
* Use GitHub Private Vulnerability Reporting or email the security maintainer directly at `security@grantsupport.io`.

---

## 4. Scope of Support

GrantSupport is 100% self-hosted, open-source software licensed under the GNU AGPLv3. Maintenance and community support are provided on a best-effort basis by repository maintainers and contributors.
