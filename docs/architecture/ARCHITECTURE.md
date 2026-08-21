# ARTIFEX — Architecture v1.0 — ACCEPTED

## Core architecture

ARTIFEX V1 is one Python application, not a microservice system.

Six logical Core components:

1. **Project Model & Store**
2. **Workflow Engine**
3. **Validation**
4. **Integration Registry**
5. **Compilation Layer**
6. **Knowledge & Evolution**

All external surfaces call the same **Application API**.

## Logical view

User / Hermes / Codex / Claude
        |
    Interface Pack
        |
  Skills + CLI/MCP
        |
  Application API
        |
+------------------------------+
| Project Model & Store        |
| Workflow Engine              |
| Validation                   |
| Integration Registry         |
| Compilation Layer            |
| Knowledge & Evolution        |
+------------------------------+
        |
 Git / Filesystem canonical truth

## Project Model & Store

Owns semantic artifacts, stable IDs, dependencies, content fingerprints, Git baseline awareness, external-edit reconciliation and STALE propagation.

Canonical semantic meaning remains reconstructable from repository artifacts.

## Workflow Engine

Owns stages, allowed transitions, required inputs/outputs, autonomy policy and liveness guards. It does not know vendor-specific harness internals.

## Validation

Owns Acceptance Contracts, typed validators, Evidence Ledger, gate evaluation, waivers and evidence freshness.

Executor claims are not canonical acceptance.

## Integration Registry

An Integration advertises capability roles:
- interface
- harness
- implementer
- research_provider

Policy is capability-based rather than vendor-name branching.

## Compilation Layer

Compiles canonical Project Model into:
- Context Packets
- Execution Packets
- human documentation
- machine context/views
- implementation dashboard

Generated views are not canonical source of truth.

## Knowledge & Evolution

V1 supports lessons, project/instance knowledge, Improvement Proposals and candidate overlays. Core self-modification is prohibited.

## Canonical storage

**Git/files own meaning.**

V1:
- filesystem/Git ProjectStore;
- lightweight file/JSONL runtime state;
- no mandatory DB.

V2 may introduce SQLite for durable runs/index/metrics/coordination without moving semantic project truth out of the repository.

## Integration policy

**Hermes-preferred, interface-neutral, executor-neutral.**

Codex standalone and Claude standalone are first-class configurations.

## External contracts

Two stable external interaction families:
- Agent Skills: methodology/context behavior.
- CLI/MCP: semantic operations and project state management.

MCP defaults to local stdio.

## Brownfield

Meaningful changes use lightweight `ChangeSet` artifacts, not a separate subsystem.

## Research

ResearchProvider is an Integration role. Pandora is an optional provider behind `ResearchRequest` / `ResearchBundle`, never a Core dependency.

## Security/trust

External repos/web/docs are data, not instruction authority.
Secrets are referenced, not stored in canonical artifacts/evidence/knowledge.
Self-improvement may not expand execution privileges.

## V2/V3 forward seams

V2:
- SQLite RunStore
- task DAG scheduler
- parallel workers
- harness routing
- cross-project knowledge
- replay
- auto overlay rebase
- methodology import
- optional Maestro integration

V3:
- dynamic workflow composition from approved stage types
- outcome-directed execution
- continuous maintenance
- assumption/ADR monitoring
- methodology evaluation
- validator effectiveness learning
- distributed execution / optional server
