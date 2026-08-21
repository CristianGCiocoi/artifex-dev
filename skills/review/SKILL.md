---
name: review
description: Independently verify ARTIFEX deliverables against frozen acceptance contracts, invariants, interfaces, baselines, and evidence requirements. Use for code review, task validation, integration conformance, milestone review, or stale-evidence assessment.
---

# ARTIFEX Review

1. Reconstruct the frozen contract, base commit, Project Model fingerprint, ownership, and relevant invariants.
2. Inspect the actual diff and artifacts; ignore executor claims as proof.
3. Run deterministic validators first, then bounded structured inspection where judgment is required.
4. Check stale baseline, scope violation, weakened criteria, self-certification, secret leakage, and vendor branching outside adapters.
5. Record measured evidence, failures, and reproduction details with exact provenance.
6. Report `PASS`, `FAIL`, `BLOCKED`, or `REBASE_REQUIRED`. Only Core-authorized evaluation may transition canonical acceptance.

Keep the reviewer independent of the executor whenever the gate requires it.
