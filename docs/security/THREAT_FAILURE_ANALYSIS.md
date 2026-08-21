# ARTIFEX — Architecture Threat & Failure Analysis

Architecture review verdict: **PASS WITH REQUIRED AMENDMENTS**, all amendments incorporated into Architecture v1.0.

## Required failure scenarios

- **F-PREMATURE-DONE:** executor reports completion with remaining work.
- **F-SELF-CERTIFICATION:** executor validates its own incorrect work.
- **F-GATE-TAMPERING:** acceptance is weakened after work begins.
- **F-EVIDENCE-SPOOFING:** validator/evidence can be trivially fabricated.
- **F-STALE-EVIDENCE:** code/model changes after evidence passed.
- **F-CONTEXT-FATIGUE:** long context produces narrowing/premature wrapping.
- **F-INTEGRATION-GAP:** tasks pass independently but system fails after integration.
- **F-REPORT-DRIFT:** human report metrics disagree with measured state.
- **F-WAIVER-ABUSE:** difficult requirements are silently abandoned.
- **F-VALIDATOR-EXECUTION:** validation command is itself a security boundary.
- **F-VENDOR-BREAK:** Hermes/Codex/Claude/DeepSeek update becomes incompatible.
- **F-INTERFACE-DISCONTINUITY:** project cannot continue after switching interfaces.
- **F-EXTERNAL-INSTRUCTION-INJECTION:** README/web/repo text attempts to control the agent.
- **F-SECRET-LEAK:** evidence/logs/knowledge capture credentials.
- **F-MEMORY-CONTAMINATION:** project-specific knowledge contaminates broader scope.
- **F-SELF-EVOLUTION-DRIFT:** local changes become incompatible with upstream updates.
- **F-WORKFLOW-LOOP:** research/architecture or other stage cycles make no progress.
- **F-STALE-WORKER:** worker finishes against an obsolete base commit/model fingerprint.
- **F-PARALLEL-CONFLICT:** concurrent workers modify shared authority surfaces.
- **F-BEGINNER-RUBBER-STAMP:** novice user approves high-impact decisions without understanding them.
- **F-RESOURCE-MISMATCH:** declared resource envelope conflicts with measured/actual environment.
- **F-RUNSTORE-CORRUPTION-V2:** future SQLite runtime state is corrupted.
- **F-DYNAMIC-WORKFLOW-PRIVILEGE-V3:** future workflow evolution attempts to expand privileges.

## Architecture protections

- Core-owned canonical transitions.
- immutable/fingerprinted Acceptance Contracts.
- Evidence Ledger bound to source commit and relevant contract/model fingerprints.
- hierarchical task/integration/milestone/release gates.
- typed validators; arbitrary shell strings are not the default validation contract.
- explicit WAIVED vs BLOCKED vs FAIL.
- stale propagation and reconciliation.
- Execution Packets tied to base commit/fingerprint.
- liveness/no-progress guard.
- external-content instruction trust boundary.
- evidence minimization and secret scrubbing.
- memory scope/promotion policy.
- compatibility/conformance suite per integration.
- update candidate/replay/atomic activation.
- privilege ceiling for self-improvement.
- Git/files canonical truth so runtime DB corruption cannot destroy semantic project state.

## Residual risks accepted

ARTIFEX is not a host-security sandbox or forensic immutable ledger. A local OS user may modify repository files or rewrite Git history. ARTIFEX detects/reconciles and validates; it does not claim to make the host tamper-proof.
