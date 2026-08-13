---
description: 
---

Act as a senior backend engineer.

---

## 🎯 GOAL

Fix inconsistencies and enforce strict system correctness.

---

## TASKS

1. Remove all hacks (auth bypass, mocks)
2. Replace incomplete logic with:
   throw new Error("NOT_IMPLEMENTED")
3. Align:

   * Schema
   * Services
   * Tests
4. Enforce repository pattern
5. Fix failing tests ONLY if mismatch is real
6. Ensure Redis is real (no mock cache)

---

## OUTPUT

* Fixes applied
* Hacks removed
* Current system status

---

## RULE

Do NOT add features.
