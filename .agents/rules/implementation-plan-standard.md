

# IMPLEMENTATION PLAN DETAIL STANDARD (MANDATORY)

Every implementation plan produced for this project MUST meet the following minimum specificity bar. Vague, high-level plans that only list file paths and batch groupings are REJECTED.

## Required Sections per Plan

1. **Source File Inventory**: Explicitly list EVERY source file being translated/migrated, not just the target output. Include the full path, line count, and what it does in one sentence.

2. **Method-by-Method Mapping Table**: For each source file, provide a table mapping EVERY public method from the source to the exact Go function signature in the target, including:
   - Original method name
   - Go method signature with full parameter types and return types
   - Cache behavior (wrap/invalidate/none)
   - Transaction requirements (tx block / standalone)

3. **Struct/Type Definitions**: Show the exact Go struct definitions for all projections, DTOs, and input types — not just names, but fields with types and JSON tags.

4. **Infrastructure Dependencies**: Identify ALL foundational/shared files the target code depends on (e.g., base classes, middleware, hooks, connection managers). These must be planned BEFORE the files that depend on them.

5. **Schema/Model Mapping**: For any ORM work, map each source model to the target schema definition, referencing exact line numbers in the source schema file.

6. **Security & Isolation Rules**: Explicitly state how multi-tenant isolation, immutability enforcement, and injection prevention are handled per file — not as a generic footnote.

7. **Verification Gates**: Define concrete, per-batch verification commands (build, generate, test) that must pass before proceeding to the next batch.

## Anti-Patterns (FORBIDDEN)

- ❌ Plans that only say "migrate X to Y" without showing HOW
- ❌ Listing file paths without method-level detail
- ❌ Omitting foundational infrastructure files that repositories depend on
- ❌ Generic "follow the same pattern" without specifying what the pattern IS
- ❌ Saying "similar to Batch 1" for later batches without at least listing key methods and new schemas needed
