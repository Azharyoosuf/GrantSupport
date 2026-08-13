# Workspace Coding Rules & Guidelines (TenantPro Go Migration)

## 1. Documentation-First Coding Rule (MANDATORY)
For every line of code written, modified, or patched in this repository, you MUST ensure that appropriate documentation is created or updated. This is to reduce developer context-switching, eliminate technical debt, and ensure AI readiness.

### Inline Code Documentation Standard:
*   **Exported & Public Symbols**: Every exported function, struct, interface, method, package, or constant MUST have a descriptive GoDoc docstring starting with the symbol name.
*   **Variable & Constant Naming**:
    *   Embed units of measure directly in names (e.g., `timeoutMs`, `priceInCents`, `fileSizeInBytes`).
    *   Do not write "magic values"; define them as top-level constants with documentation.
*   **Comments for "Why", Not "What"**: Inline comments must describe the business rationale or technical constraints (e.g., rate limits, multi-tenant isolation, Valkey caching requirements), not simply repeat what the code does.

### External Documentation Updates:
*   **API & Core Feature Changes**: If you add or change an API route or schema, you must update the OpenAPI specification and database schemas.
*   **Architectural Shifts**: If you change any architecture pattern or add core abstractions, you must document it as an Architectural Decision Record (ADR) under `code documentation/go documentation/adr/`.
*   **Categorization**: If the new feature requires setup or operational guidelines, update or add a file under:
    *   `code documentation/go documentation/tutorials/` for onboarding.
    *   `code documentation/go documentation/how-to/` for technical implementation workflows.
    *   `code documentation/go documentation/reference/` for factual specifications.

---

## 2. Zero-Stub & Full-Parity Migration Mandate (MANDATORY)
Zero-stub policy and migration parity requirements are defined in `.agents/rules/zero-stub-policy.md` and `.agents/rules/migration-parity-completeness.md` — read those files directly rather than relying on a summary here.

---

## 3. Go Presentation Layer Mandates (MANDATORY)
* **Thin Controller Mandate**: Controllers handle HTTP I/O ONLY. Zero business logic or ORM queries. Every handler method MUST NOT exceed 15 lines, and single files MUST NOT exceed 100 lines.
* **Zero Boilerplate Error Handling**: All HTTP handlers MUST return `error` and be wrapped in the `CatchAsync` higher-order handler function.
* **Struct-First Validation**: Request payloads MUST be validated using `DecodeAndValidate[T](r)` with `go-playground/validator/v10` struct tags (`validate:""`) before calling Services.
* **RFC 7807 Standard**: All HTTP error responses MUST output standard RFC 7807 Problem Details (`type`, `title`, `status`, `detail`).
* **Multi-Tenant Context Safety**: Extract `institution_id` safely from `pkgctx.GetTenant(r.Context())` and pass it explicitly to every service invocation.
