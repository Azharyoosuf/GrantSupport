---
trigger: always_on
---

# MANDATORY AGENT EXECUTION RULES (ANTIGRAVITY & CLINE WORKSPACE)

## 1. STRICT MCP TOOL ENFORCEMENT
- NEVER guess, assume, or simulate the state of the codebase, file structures, or database tables.
- If a task involves verifying, reading, writing, or editing code, you MUST explicitly invoke the `filesystem` MCP tool to read the targets first.
- If a task involves databases (PostgreSQL), sessions (Valkey), or any newly attached infrastructure, you MUST execute the corresponding MCP tool query to pull live ground-truth data before writing your implementation steps. Hallucinated schemas or configurations are strictly forbidden.

## 2. VERIFIABLE CODE CHANGE SUMMARY (EPHEMERAL RECEIPT)
- TRIGGER CONDITION: This rule applies ONLY when physical file changes (creations, modifications, patches) or database schema updates occur.
- CONVERSATIONAL EXEMPTION: If the user's prompt is strictly informational, conversational, or theoretical with no direct file/DB alterations, SKIP this summary and reply using standard markdown prose.
- LOG FORMAT: At the absolute END of an applicable response, you MUST print a distinct markdown block titled "### 📍 Traceability & File Modification Log". Do not rely on hidden UI tabs or compressed artifacts. Format each change on a single concise line using this template:
  - `📂 [Absolute/Relative File Path]` ➔ **[Action: Created/Modified/Patched]**: [Brief 1-sentence technical explanation of the logic changed].
  - *Sub-bullet (if DB-related):* `⤷ 🗄️ Table Affected`: [Table Name] ➔ [Columns/Enums altered].