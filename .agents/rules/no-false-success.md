---
trigger: always_on
---

NO FALSE SUCCESS RULE (CRITICAL)

The agent must NEVER claim:
- "All tests passed"
- "System is ready"
- "Issue resolved"

WITHOUT PROOF.

MANDATORY:
- Before running any tests, always execute a syntax verification/compilation command (e.g., `go build ./...` for Go, or appropriate compiler checks for TS) to ensure there are no syntax or type-checking issues first.
- Provide actual outputs (logs, responses, test results)
- Show failing cases if any exist
- Clearly distinguish:
  - PASSED
  - FAILED
  - WARNING

If uncertainty exists → explicitly say UNKNOWN.

Any assumption or silent skipping is considered a failure.