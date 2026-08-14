# Contributing to GrantSupport

Thank you for your interest in contributing to GrantSupport! We welcome bug reports, documentation improvements, and code contributions.

---

## Code of Conduct

Please be respectful, constructive, and collaborative in all communications.

---

## Development Setup

### Prerequisites

- **Go**: Version `1.24` or later
- **Git**
- **Docker & Docker Compose** (optional, for local PostgreSQL/MySQL/Valkey integration testing)

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

## Testing Guidelines

GrantSupport enforces strict test integrity:

1. **Unit & Functional Tests**:
   ```bash
   go test -v -count=1 ./...
   ```

2. **Race Detection** (Mandatory before submitting PRs):
   ```bash
   go test -v -race -count=1 ./...
   ```

3. **Code Formatting**:
   Ensure all Go files adhere to standard formatting:
   ```bash
   gofmt -w .
   ```

---

## Submitting Pull Requests

1. Fork the repository and create a descriptive feature branch:
   ```bash
   git checkout -b fix/issue-description
   ```
2. Commit your changes with clear, concise commit messages.
3. Ensure all tests and race detector checks pass cleanly.
4. Open a Pull Request targeting `main` with a summary of the change and associated test results.

---

## License

By contributing to GrantSupport, you agree that your contributions will be licensed under the [Business Source License 1.1 (BSL 1.1)](LICENSE).
