---
name: implementation-plan
description: Compile accepted ARTIFEX requirements and architecture into executable milestones, owned tasks, immutable acceptance contracts, gates, and rollback-aware execution packets. Use when preparing implementation work after design authority is accepted.
---

# ARTIFEX Implementation Plan

1. Use accepted requirements and architecture as authority; keep candidate material out of executable scope.
2. Decompose work into dependency-ordered milestones and tasks with stable IDs.
3. Give each task explicit file and surface ownership, required capabilities, inputs, outputs, and forbidden operations.
4. Freeze acceptance criteria, deterministic validators, evidence requirements, base commit, Project Model fingerprint, and expected result status.
5. Define integration and milestone gates plus rollback or rebase behavior.
6. Compile minimum sufficient, transcript-independent Execution Packets. Map stale results to `REBASE_REQUIRED`.

Do not infer deployment or acceptance authorization from an implementation plan.
