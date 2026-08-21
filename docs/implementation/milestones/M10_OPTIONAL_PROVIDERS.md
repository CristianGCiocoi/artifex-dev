# M10 — Optional Providers: DeepSeek Harness + Pandora

M10 may run after M4 and does NOT block Core V1 GA.

## A — DeepSeek Harness

- **M10-T01** version/capability detection
- **M10-T02** headless harness adapter using stable product boundary
- **M10-T03** implementation result/cancel/failure mapping
- **M10-T04** conformance suite
- **M10-T05** compatibility/preview fail-closed policy
- **M10-T06** optional interface role only if a stable useful surface exists; do not couple to Cordis internals

## B — Pandora Research

- **M10-T07** filesystem ResearchRequest export
- **M10-T08** ResearchBundle import/validation
- **M10-T09** PandoraResearchAdapter
- **M10-T10** DEEP research policy integration
- **M10-T11** authority test: Pandora cannot transition Project Model state
- **M10-T12** future transport seam preserving contract

## Gate
Each pack has independent PASS/FAIL release status. Pack failure never changes Core GA status.
