---
trigger: always_on
---

# MIGRATION STABILITY RULE (STRICT)

We are in the ACTIVE MIGRATION PHASE (TypeScript to Go).

## DO NOT:
- Add net-new product features not defined in the original TypeScript codebase or the PRD.
- Bypass database constraints or use mock drivers for Valkey in integration tests.
- Allow dynamic response structural differences between Node.js and Go APIs.
- Declare a layer "complete" based on successful compilation alone — a missing method does NOT cause a build failure. Silence is not parity.

## MANDATORY:
- Enforce Go Repository pattern: No Ent/pgx queries inside controllers or services.
- Maintain strict multi-tenant isolation: every query must filter or validate against `institution_id`.
- Ensure all Go APIs implement RFC 7807 compliance for validation and error handling.
- Verify cross-language functional equivalence for core APIs.
- Run `python tools/parity_audit.py` after every migration batch and include the output verbatim as proof.

## MIGRATION IS NOT COMPLETE UNLESS:
- `python tools/parity_audit.py` reports CRITICAL=0 for Controller, Service, and Repository layers.
- Every TypeScript handler, service method, and repository method has a verified Go equivalent registered and callable.
- Every Go handler is registered as a live route in `pkg/router/router.go`.
- Tests model real-world production situations (e.g., concurrent requests, validation edge cases, network retries) — not minimal synthetic assertions.
- No temporary mock bypasses exist in any ported endpoints.
- Tests use live test databases and Valkey instances — not in-memory mocks.
- The critical end-to-end path has been fully verified in Go:
  Student → Bill → Payment → Ledger

Always prioritize architectural correctness and data isolation over passing tests.
