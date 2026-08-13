# ZERO-STUB & FULL-PARITY MIGRATION MANDATE (CRITICAL)

### Mandatory Execution Requirements:

1. **ZERO-STUB & ZERO-PLACEHOLDER POLICY**:
   - The agent is STRICTLY FORBIDDEN from writing, generating, or leaving shortened placeholder stubs, empty/partial iteration loops, hardcoded mock returns, or dummy fallback structures in any service, repository, model, or controller file.
   - Every method, business rule, dynamic rate lookup, fallback chain, database transaction, and calculation present in the original source code MUST be ported with 100% full production fidelity.

2. **DOCUMENT GENERATION & REPORTING PARITY**:
   - All document generation routines (PDF buffers, Excel/CSV spreadsheets, data portability packages) MUST be fully connected to live database query repositories.
   - Never write header-only or schema-only stubs for export routines. All data iteration loops, KMS PII decryption calls, formatting rules, and SHA-256 checksum calculations MUST be 100% executed.

3. **VERIFIABLE PARITY & BUILD GATES**:
   - Before declaring any file, batch, or phase completed, the agent MUST:
     a. Execute `go build ./...` and confirm exit code 0.
     b. Execute `python tools/parity_audit.py` and confirm CRITICAL gap count has decreased for the target layer.
     c. Produce a side-by-side method count showing: `TS methods: N | Go handlers: M | Gap: N-M = 0`.
   - Any code containing `TODO`, `FIXME`, dummy return values, or skipped logic will be treated as a critical task failure.

4. **SILENT OMISSION IS A STUB**:
   - A method that exists in TypeScript but is simply not written in Go is EQUIVALENT to a stub.
   - Successful compilation does NOT prove parity. Missing methods compile silently.
   - Only `python tools/parity_audit.py` reporting CRITICAL=0 constitutes proof of parity.
