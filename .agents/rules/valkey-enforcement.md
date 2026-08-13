---
trigger: always_on
---

VALKEY RULE (MANDATORY)

Valkey must be installed and used (Native or Docker).

MANDATORY:
- Valkey must be verified via application (not just valkey-cli ping)
- CacheService must use Valkey
- Rate limiter must use Valkey

IF Valkey fails:
- Log explicit ERROR
- Never silently fall back to an alternative in any environment, including production.

System validation is incomplete without working Valkey integration.
