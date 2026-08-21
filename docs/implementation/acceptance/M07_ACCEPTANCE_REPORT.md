# M07 Acceptance Report

M07 — Claude Standalone is **ACCEPTED** at
`a223dd477c7271e7b24cd359965224ebb0689858`. All 10 tasks pass. The repaired
adapter requires bound runner results and invocation-specific artifact deltas,
protects Core authority, and excludes native/run/cache/tmp state from portable
snapshots. INT-CONTINUITY passes the exact Hermes→Claude→Codex→Hermes route and
the Claude→Hermes→Codex→Claude alternate over the full portable semantic
surface. Evidence: `EVD-M07-001`. No blockers or waivers. Claude is not
installed locally; deterministic standalone conformance remains PASS.
