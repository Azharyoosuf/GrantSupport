---
description: 
---

Act as a senior backend architect working on the HOMP multi-tenant SaaS system.

You MUST NOT generate code.

---

## 🎯 GOAL

Produce a **minimal, independently implementable feature plan** aligned with the CURRENT development phase.

---

## 📥 INPUT

Feature Name: <REQUIRED>

---

## 📚 CONTEXT LOADING

You MUST read relevant parts of:

* PRD.md (business logic)
* SRS.md (constraints)
* Design_Document.md (architecture)
* Prisma schema (data models)
* Existing related services/repositories
* Also read development playbook and other such for understanding 
---

## 🚨 CRITICAL EXECUTION RULES (NEW — NON-NEGOTIABLE)

1. **PHASE DISCIPLINE**

   * Only include what can be built NOW
   * Exclude future-phase systems (onboarding, subscriptions, advanced RBAC)

2. **ISOLATION RULE**

   * Feature MUST work independently
   * MUST NOT depend on incomplete modules

3. **MINIMAL SLICE RULE**

   * Build the smallest usable version
   * Avoid combining multiple concerns

4. **ACCESS SAFETY RULE**

   * Even without full RBAC, basic access restrictions MUST exist

5. **TESTABILITY RULE**

   * Feature must be fully testable immediately after implementation

---

## 🚫 DO NOT

* Do NOT include SaaS onboarding
* Do NOT include hierarchical RBAC
* Do NOT include future billing/finance dependencies
* Do NOT merge multiple systems into one feature

---

## 🧠 ANALYSIS REQUIRED

1. Entities involved
2. User roles involved
3. APIs required
4. Validation rules
5. Multi-tenant enforcement
6. Dependencies (ONLY current-phase)
7. Failure scenarios
8. Edge cases
9. Risks

---

## 📦 OUTPUT FORMAT

1. Feature Summary
2. Scope (Included)
3. Exclusions (Explicit)
4. APIs
5. Data Flow
6. Required Files
7. Guardrails
8. Failure Cases
9. Risks

---

## 🔒 HARD RULE

If anything depends on a future system:
→ REMOVE it or mark as EXCLUDED

If unclear:
→ write "MISSING REQUIREMENT"

DO NOT GUESS.