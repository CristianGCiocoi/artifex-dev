# M0 — Bootstrap & Architecture Contracts

## Goal
Runnable/testable skeleton with frozen implementation contracts. Do not implement downstream product behavior.

## Tasks

### M0-T01 Repository bootstrap
Set Python 3.12+ policy, `uv`, package metadata, lint/type/test/coverage/CI and version source.

### M0-T02 Package boundaries
Create logical packages:
`project`, `workflow`, `validation`, `integrations`, `compilation`, `knowledge`, `application`.
Add architecture tests preventing prohibited imports/cycles.

### M0-T03 Identity/schema primitives
Implement stable ID parsing/validation/serialization for requirement, decision, invariant, milestone/task, validation/evidence/waiver, lesson/improvement/change IDs.

### M0-T04 Application API foundation
Define transport-independent OperationRequest/Result/Error/Context and operation registry. Smoke operations only: system.version/system.health.

### M0-T05 Store contracts
Define `ProjectStore` and `RunStore` seams with minimal filesystem fixtures. No SQLite semantics.

### M0-T06 Native packaging POC
Compare PyInstaller/Nuitka/viable alternative on Windows/Linux/macOS target criteria. Produce ADR-PACKAGING-001.

### M0-T07 Test taxonomy/golden fixtures
Create suite markers and reusable fixture repositories for valid/minimal/deep/malformed/stale/brownfield cases.

### M0-T08 Traceability baseline
Map accepted requirements→architecture components→implementation milestones. 100% requirement ownership.

### M0-T09 Dashboard state contract
Formalize dashboard data model without building full HTML renderer.

### M0-T10 Authority/trust baseline
Encode accepted authority/instruction/secret/privilege principles as contracts/policies needed by later milestones.

## Parallel waves

Wave 1: T01 + T07.
Wave 2: T02 + T03 + T05.
Wave 3: T04 + T06 + T09 + T10 where file ownership allows.
Wave 4: T08 + full integration verification.

## Do not implement
Real workflow, Evidence Ledger, ChangeSet behavior, docs compiler, dashboard HTML, adapters, memory engine, SQLite, installer GUI, Pandora/DeepSeek integration, generic plugin system.

## Milestone gate
10/10 task gates + M0 integration smoke + architecture check + traceability 100% + CI PASS.
