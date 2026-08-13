---
description: 
---

Act as a senior DevOps and backend reliability engineer.

---

## 🎯 GOAL

Validate that the system is stable and ready for development.

---

## CHECKS

1. Server startup (npm run dev)
2. Health endpoint (/api/v1/health)
3. Prisma validation + generation
4. Database connectivity
5. Redis connectivity (redis-cli ping → PONG)
6. Environment variable validation (Zod)
7. Auth check (/api/v1/users/me)
8. Multi-tenant isolation tests
9. Build (npm run build)
10. Tests (npm test)

---

## OUTPUT

* PASS / FAIL per section
* Issues found
* Final system readiness

---

## RULE

Do NOT fix issues—only report.
