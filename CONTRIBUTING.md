# Contributing to GrantSupport

Thank you for your interest in contributing to GrantSupport! GrantSupport is a community-driven, open-source security engine licensed under the **[MIT License](LICENSE)**.

We welcome bug reports, security disclosures, documentation improvements, and pull requests.

---

## Code of Conduct

Please be respectful, constructive, and collaborative in all issues, pull requests, and discussions. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for details.

---

## Development Setup

### Prerequisites
- **Go**: Version `1.22` or later
- **Git**
- **Docker & Docker Compose** (for running PostgreSQL 16, MySQL 8.4, MariaDB 11.4, and Valkey 7.2 test backends)
- **Make** (optional, for standard build targets)

### Clone & Build
```bash
git clone https://github.com/Azharyoosuf/GrantSupport.git
cd GrantSupport

# Verify compilation
go build ./...

# Run static analysis
go vet ./...
```

---

## Testing Standards

All code contributions must include comprehensive test coverage:

1. **Unit & Functional Tests**:
   ```bash
   go test -v -count=1 ./...
   ```

2. **Race Detection (Mandatory for PRs)**:
   ```bash
   go test -v -race -count=1 ./pkg/service/... ./pkg/adapters/...
   ```

3. **Code Formatting**:
   Ensure all Go files adhere to standard `gofmt`:
   ```bash
   gofmt -w .
   ```

4. **Makefile Shortcuts**:
   ```bash
   make test        # Run all unit and integration tests
   make test-race   # Run tests with Go race detector
   make vet         # Run static analysis
   make build       # Compile standalone server binary
   ```

---

## Contributor Core Rules

When proposing code changes to GrantSupport:

1. **Zero Telemetry / Zero Phone-Home**: Never introduce telemetry, phone-home, heartbeat, machine fingerprinting, or remote license checks. GrantSupport is 100% self-hosted.
2. **Fail-Closed Security**: Never introduce silent fallbacks that allow unauthenticated access or unverified session state during infrastructure outages. If a revocation or rate-limiting dependency fails during a request, it must fail closed with an explicit error.
3. **Multi-Tenant Isolation**: Ensure every database query, cache key, and audit event enforces strict `institution_id` isolation.
4. **Documentation Synchronization**: If your PR modifies, adds, or removes an API endpoint, DTO field, or configuration parameter, you MUST update [`api/openapi.yaml`](api/openapi.yaml) and the corresponding documentation in [`docs/`](docs/).

---

## Submitting Pull Requests

1. Fork the repository and create a descriptive feature branch:
   ```bash
   git checkout -b fix/issue-description
   ```
2. Commit your changes with clear, descriptive commit messages.
3. Ensure `go build ./...`, `go vet ./...`, and `go test -race ./...` all pass with zero errors or warnings.
4. Open a Pull Request against the `main` branch.
5. Provide a clear summary of what problem was solved and include test output proof.

---

## License Agreement

By contributing to GrantSupport, you agree that your contributions will be licensed under the **[MIT License](LICENSE)** as stated in the [`LICENSE`](LICENSE) file.
