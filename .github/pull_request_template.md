## Description
Provide a concise explanation of what changes were made and why.

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update
- [ ] Security hardening / test improvement

## Verification & Proof
Describe the tests you ran to verify your changes. Include terminal command outputs where applicable:
- [ ] `go build ./...` passes
- [ ] `go vet ./...` passes
- [ ] `go test -v -count=1 ./...` passes
- [ ] `go test -v -race ./...` passes (mandatory for concurrency/store changes)
- [ ] `api/openapi.yaml` updated (if API contracts changed)
- [ ] Documentation updated (if features/parameters changed)

## Checklist
- [ ] My code follows the repository style and Go idioms.
- [ ] I have not introduced any telemetry, phone-home, or remote tracking mechanisms.
- [ ] I have not weakened any fail-closed security behaviors.
- [ ] I agree that my contributions are licensed under AGPL-3.0-only.
