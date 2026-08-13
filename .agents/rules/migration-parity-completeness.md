# MIGRATION PARITY COMPLETENESS RULE (MANDATORY)

> **Root Cause This Rule Prevents**: During Phase 3 migration, 78 controller handlers and 45 service methods existed in the TypeScript source but were NEVER ported to Go. The Go codebase compiled successfully and tests passed because the missing methods were simply absent — not broken. This rule exists to make that class of silent omission impossible.

---

## 1. The Parity Audit Requirement (Before and After Every Migration Batch)

- **BEFORE** starting any migration batch, the agent MUST run `python tools/parity_audit.py` and record the baseline gap count per layer.
- **AFTER** completing any migration batch, the agent MUST re-run `python tools/parity_audit.py` and prove the gap count for that layer has dropped.
- A batch MAY NOT be declared complete if the CRITICAL gap count for its layer is unchanged or higher than the baseline.
- The parity audit output MUST be included verbatim in the completion proof — not summarized.

## 2. Three-File Completeness Mandate (The Golden Triangle)

Every feature ported from TypeScript to Go is ONLY complete when ALL THREE of the following exist and are verified:

| # | Artifact | Verification Command |
|:--|:---|:---|
| 1 | **Go handler method** in the correct `*_controller.go` file | `grep -n "func.*MethodName" pkg/controller/*.go` |
| 2 | **Route registered** in `pkg/router/router.go` | `grep -n "MethodName" pkg/router/router.go` |
| 3 | **Service method** called by the handler exists | `grep -n "func.*MethodName" pkg/service/*.go` |

If ANY of the three is missing → the feature is **NOT ported**. Claiming otherwise is a critical rule violation.

## 3. Side-by-Side Method Count Gate

Before declaring a controller file complete, the agent MUST produce a side-by-side method count:

```
TS source  : src/presentation/controllers/XController.ts   → N methods
Go target  : go-backend/pkg/controller/x_controller.go     → M handlers
Difference : N - M = D gaps remaining
```

If D > 0, the file is incomplete. No exceptions. The agent MUST enumerate every missing method name explicitly.

## 4. Parity Audit Tool Location

- Script: `d:/Hostel_management/tools/parity_audit.py`
- Markdown report: `d:/Hostel_management/tools/parity_report.md`
- JSON report: `d:/Hostel_management/tools/parity_report.json`

The parity audit script MUST be kept current. If new TypeScript controllers, services, or repositories are added, the `RENAME_MAP` in `parity_audit.py` must be updated to reflect any semantic renames between TS and Go method names.

## 5. Current Known Gap State

Do not trust any parity number stated in this file or any other document. Always run `python tools/parity_audit.py` and use its live output as ground truth.

## 6. Forbidden Completion Claims

The agent MUST NEVER say any of the following without attaching `parity_audit.py` output proving zero gaps for the relevant layer:

- "Phase X is complete"
- "All controllers have been ported"
- "Migration is done"
- "The presentation layer is fully implemented"
- "All service methods are in place"

Violating this rule is treated the same as fabricating test results.
