# Multi-Agent Workflow Architecture (TenantPro Go Migration)

## Overview

This rule defines the **mandatory multi-agent hierarchy** for all development work in this
repository. Every non-trivial code change MUST pass through this pipeline in order.
No agent may declare a task "complete" — only the **Parent Orchestrator** may do so,
and only after all downstream agents have signed off.

---

## Agent Hierarchy

```
┌─────────────────────────────────────────────────┐
│          PARENT ORCHESTRATOR (Level 0)           │
│  Rules Enforcement · Quality Gate · Final Sign-off│
└────────────────────┬────────────────────────────┘
                     │  spawns & coordinates
     ┌───────────────┼───────────────────┐
     ▼               ▼                   ▼
┌─────────┐   ┌──────────────┐   ┌──────────────────┐
│  DEV    │   │   PARITY     │   │  DOCUMENTATION   │
│ AGENT   │   │  AUDITOR     │   │     AGENT        │
│(Level 1)│   │ (Level 1)    │   │   (Level 1)      │
└────┬────┘   └──────┬───────┘   └──────────────────┘
     │               │ feeds into
     ▼               ▼
┌──────────────────────────┐
│   CODE REVIEWER +        │
│   SECURITY/BUG AGENT     │
│       (Level 2)          │
└─────────────┬────────────┘
              │
              ▼
        ┌──────────┐
        │  TESTER  │
        │  AGENT   │
        │(Level 3) │
        └──────────┘
```

---

## Agent Definitions & Mandates

### 1. Parent Orchestrator (Level 0) — THE GATEKEEPER
**Trigger**: All tasks. It is invoked first and last.
**Responsibilities**:
- Reads and enforces ALL rules in `.agents/rules/` and `.agents/AGENTS.md` before spawning sub-agents.
- Decomposes the task into sub-task contracts and assigns them to child agents.
- Blocks any child agent from being skipped, reordered, or short-circuited.
- Receives sign-off reports from all child agents before issuing final completion.
- Runs `go build ./...` independently at the end to confirm zero compilation errors.
- Runs `python tools/parity_audit.py` as a final gate; MUST attach verbatim output.
- Any Output Contract from a child agent that is not backed by an actual tool call executed in this session is invalid — reject it and re-dispatch the child agent. Narrated or assumed command output is treated the same as a fabricated test result.

**Forbidden Actions**:
- May NOT write implementation code.
- May NOT approve a task if any child agent has reported a FAIL or UNKNOWN.
- May NOT skip the Parity Auditor or Documentation Agent, even for "minor" fixes.

---

### 2. Developer Agent (Level 1) — THE IMPLEMENTER
**Trigger**: Spawned by Parent after task decomposition.
**Responsibilities**:
- Implements all Go handlers, services, repositories, and DTOs.
- Enforces the Three-File Golden Triangle: `*_controller.go` + `router.go` + `*_service.go`.
- Every method must be production-quality — zero stubs, zero hardcoded return values.
- Enforces multi-tenant isolation (`institution_id`) on every DB query.
- Enforces Thin Controller Mandate: handlers ≤ 15 lines, controller files ≤ 100 lines.
- Runs `go build ./...` after every file batch to verify clean compilation before handing off.

**Output Contract** (must be delivered to Parent):
```
Files Created/Modified: [list]
go build exit code: 0
Side-by-side method count: TS methods: N | Go handlers: M | Gap: 0
```

**Forbidden Actions**:
- May NOT write documentation, tests, or audit reports.
- May NOT declare "done" — it hands off to the Code Reviewer.

---

### 3. Parity Auditor Agent (Level 1) — THE MIGRATION VERIFIER
**Trigger**: Spawned by Parent after every migration batch (Controller, Service, or Repository layer).
**Responsibilities**:
- Runs `python tools/parity_audit.py` and attaches **verbatim** output — no summaries.
- Verifies Controller CRITICAL = 0, Service CRITICAL = 0, Repository CRITICAL = 0.
- Cross-checks that every ported method appears in all three layers (Golden Triangle audit).
- Reports WARNING-level gaps to the Parent even if CRITICAL = 0.
- Blocks forward progress if any CRITICAL gap remains.

**Output Contract** (must be delivered to Parent):
```
python tools/parity_audit.py output:
[verbatim output pasted here]

Controller CRITICAL: N  | PASS/FAIL
Service CRITICAL:    N  | PASS/FAIL
Repository CRITICAL: N  | PASS/FAIL
WARNING count:       N  | (list if > 0)
```

**Forbidden Actions**:
- May NOT modify source code.
- May NOT summarize or paraphrase audit output — verbatim only.
- May NOT pass if CRITICAL > 0 for the layer under review.

---

### 4. Documentation Agent (Level 1) — THE CHRONICLER
**Trigger**: Spawned by Parent in parallel with the Developer Agent after implementation.
**Responsibilities**:
- Enforces Documentation-First Rule (AGENTS.md §1) on every file touched by the Developer.
- Verifies every exported Go symbol has a GoDoc comment starting with the symbol name.
- Creates or updates ADR files under `code documentation/go documentation/adr/` for any architectural change.
- Updates API specs (OpenAPI) if routes were added or changed.
- Writes how-to guides under `code documentation/go documentation/how-to/` for new patterns.
- Checks that variable/constant names embed units of measure (e.g., `timeoutMs`, `priceInCents`).

**Output Contract** (must be delivered to Parent):
```
Symbols documented: N/N (all exported symbols covered)
ADRs created/updated: [list or "none required"]
OpenAPI updated: YES/NO/NOT_APPLICABLE
How-to guides updated: [list or "none required"]
Documentation gaps: [list any symbols still missing docs, or "NONE"]
```

**Forbidden Actions**:
- May NOT modify business logic.
- May NOT approve if any exported symbol lacks a GoDoc comment.

---

### 5. Code Reviewer + Security & Bug Agent (Level 2) — THE CRITIC
**Trigger**: Spawned by Parent after Developer Agent completes and Documentation Agent signs off.
**Responsibilities**:
- Reviews all code produced by the Developer for:
  - RFC 7807 compliance on all error responses.
  - Zero ORM queries inside controllers or services (Repository-only DB access).
  - Multi-tenant isolation — every DB query must filter by `institution_id`.
  - Argon2id for password hashing, RS256 for session signing.
  - AWS KMS envelope encryption for all student/staff PII.
  - Append-only ledger enforcement (no DELETE/UPDATE on financial tables).
  - Redlock usage on all shared resources (beds, cash allocations).
  - No hardcoded secrets, credentials, or magic values.
  - No N+1 query patterns.
  - Input validation via `DecodeAndValidate[T]` on all handlers.
- Reports every vulnerability as CRITICAL, HIGH, MEDIUM, or LOW with file + line reference.
- Must pass a Go vet check: `go vet ./...`.

**Output Contract** (must be delivered to Parent):
```
go vet ./... exit code: 0
Security findings:
  CRITICAL: N  [list with file:line]
  HIGH:     N  [list with file:line]
  MEDIUM:   N  [list with file:line]
  LOW:      N  [list with file:line]
Architecture findings:
  [list or "NONE"]
Overall verdict: PASS / FAIL / PASS_WITH_WARNINGS
```

**Forbidden Actions**:
- May NOT modify source code directly — must file findings to the Parent, who re-dispatches to the Developer.
- May NOT pass if any CRITICAL or HIGH vulnerability is unresolved.

---

### 6. Tester Agent (Level 3) — THE VALIDATOR
**Trigger**: Spawned by Parent only after the Code Reviewer signs off with PASS or PASS_WITH_WARNINGS.
**Responsibilities**:
- Writes and runs integration tests against live test databases (PostgreSQL) and live Valkey instances — no in-memory mocks.
- Tests must cover real-world scenarios: concurrent requests, validation edge cases, multi-tenant isolation boundary tests.
- Verifies the critical end-to-end path in Go: `Student → Bill → Payment → Ledger`.
- Runs `go test ./... -race -count=1` and attaches full output.
- Verifies no test uses mock DB drivers or bypasses Valkey for rate limiting.
- Reports each test result as PASSED, FAILED, or UNKNOWN.

**Output Contract** (must be delivered to Parent):
```
go test ./... -race -count=1 output:
[verbatim output pasted here]

PASSED:  N tests
FAILED:  N tests [list]
UNKNOWN: N tests [list]
E2E path (Student → Bill → Payment → Ledger): VERIFIED / NOT_VERIFIED
Race conditions detected: YES/NO
Overall verdict: PASS / FAIL
```

**Forbidden Actions**:
- May NOT use in-memory test databases, mock Valkey, or mock KMS.
- May NOT pass if any test is FAILED or UNKNOWN.
- May NOT silently skip flaky tests — must report them as FAILED.

---

## Mandatory Pipeline Order

```
Task Intake
    │
    ▼
[1] Parent Orchestrator  ──── reads all rules, decomposes task
    │
    ├──► [2] Developer Agent  ──── implements, builds, hands off
    │         └── go build ./... MUST exit 0 before handoff
    │
    ├──► [3] Parity Auditor Agent  ──── runs parity_audit.py, verbatim output
    │         └── CRITICAL = 0 required to proceed
    │
    ├──► [4] Documentation Agent  ──── parallel to Parity Auditor
    │         └── all exported symbols documented
    │
    ▼
[5] Code Reviewer + Security Agent  ──── reviews all output from 2+3+4
    │   └── go vet ./... MUST exit 0
    │   └── CRITICAL/HIGH findings block forward progress
    │
    ▼
[6] Tester Agent  ──── integration tests, live DB, Valkey, race detector
    │   └── go test ./... -race MUST pass
    │
    ▼
[1] Parent Orchestrator  ──── collects all sign-offs, issues final completion
```

---

## Escalation Protocol

- If **Developer** produces code that fails `go build ./...`, the task returns to Developer — it does NOT proceed downstream.
- If **Parity Auditor** reports CRITICAL > 0, the task returns to Developer for gap closure.
- If **Code Reviewer** reports CRITICAL/HIGH security finding, the task returns to Developer.
- If **Tester** reports any FAILED test, the task returns to Developer.
- If **Documentation Agent** reports undocumented exported symbols, the task returns to Developer.
- The Parent Orchestrator is the sole authority that may close a loop or escalate to the user.

---

## Do NOT Add These (Anti-Patterns)

- ❌ A "DevOps Agent" that can modify CI/CD pipelines arbitrarily — use the Developer for this.
- ❌ A "Database Migration Agent" with write access to production — use migrations reviewed by the Code Reviewer.
- ❌ Any agent that can bypass the Parity Auditor gate on the grounds of "it's a minor fix."
- ❌ Parallel execution of the Code Reviewer and Tester — the Tester MUST wait for the Reviewer to sign off.

---

## Summary Table

| Agent | Level | Blocks Pipeline? | Can Write Code? |
|---|---|---|---|
| Parent Orchestrator | 0 | YES — final gate | NO |
| Developer Agent | 1 | YES — build must pass | YES |
| Parity Auditor | 1 | YES — CRITICAL=0 required | NO |
| Documentation Agent | 1 | YES — all symbols must be documented | NO (doc comments only) |
| Code Reviewer + Security | 2 | YES — CRITICAL/HIGH block | NO |
| Tester Agent | 3 | YES — all tests must pass | NO (test files only) |
