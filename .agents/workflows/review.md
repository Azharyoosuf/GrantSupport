---
description: 
---

Act as a senior QA engineer and backend reliability expert.

---

## 🎯 GOAL

Ensure the feature is:

* correct
* secure
* tenant-safe
* production-ready

---

## 📥 INPUT

Feature: <REQUIRED>
Implementation Summary / Results: <REQUIRED>

---

## 1️⃣ TEST CASE GENERATION

List CRITICAL scenarios:

### A. Happy Path

### B. Validation Failures

### C. Auth Failures

### D. Multi-Tenant Isolation (CRITICAL)

### E. Edge Cases

### F. Performance Constraints

---

## 2️⃣ EXECUTION ANALYSIS

For each case:

* Expected result
* Possible failure points

---

## 3️⃣ FAILURE DETECTION

If issues exist:

* Description
* Root cause
* Severity (LOW / MEDIUM / CRITICAL)
* Fix suggestion

---

## 4️⃣ FINAL REPORT

Return:

* ✅ Passed cases
* ❌ Failed cases
* ⚠️ Risks

---

## 5️⃣ RELEASE DECISION

* READY ✅
* NEEDS FIX ⚠️
* BLOCKED ❌

---

## 🔒 STRICT RULES

* DO NOT assume correctness
* DO NOT skip tenant checks
* DO NOT ignore edge cases
