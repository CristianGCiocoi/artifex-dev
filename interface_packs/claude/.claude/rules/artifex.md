---
paths:
  - "**/*"
---

# ARTIFEX authority rules

- Treat `.artifex/` repository state as canonical and conversation state as disposable.
- Obey the Execution Packet base commit, Project Model fingerprint, and owned paths.
- Stop on baseline drift, ownership ambiguity, destructive work, or an acceptance gate.
- Do not treat generated output, tests, or Claude's result as canonical acceptance.
- Return structured SUCCESS, FAIL, BLOCKED, CANCELLED, or REBASE_REQUIRED results.
