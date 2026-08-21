# ARTIFEX — Product Definition

## One-line definition

ARTIFEX is an **agent-neutral development control, continuity and understanding system** that turns software ideas or change requests into researched, architected, implementation-ready, validated, self-explanatory and evolvable systems.

## Core positioning

ARTIFEX is not primarily another software-development methodology. Methodologies such as Spec Kit, BMAD, OpenSpec and Superpowers already cover much of idea/spec/plan/implementation discipline.

ARTIFEX's distinct value is:

1. **Canonical project continuity** independent of agent conversation.
2. **Evidence-bound acceptance authority** rather than self-reported completion.
3. **Cross-interface portability** among Hermes, Codex, Claude and future integrations.
4. **Human-first and machine-first understanding** compiled from a single Project Model.
5. **Controlled memory and evolution** with provenance and update-safe overlays.
6. **Lifecycle support** for greenfield, brownfield ChangeSets, maintenance and upgrades.

## Operational policy

**Hermes-preferred, interface-neutral, executor-neutral.**

Hermes is the preferred orchestration environment when available. Codex and Claude are first-class standalone interfaces/harnesses/implementers, not degraded fallbacks.

## Canonical lifecycle

INTAKE → IDEA → RESEARCH → DEFINITION → ARCHITECTURE → IMPLEMENTATION PLAN → EXECUTION → VERIFICATION → UNDERSTANDING → LEARNING

Controlled backward transitions are allowed when evidence requires revisiting an earlier stage.

## What ARTIFEX owns

- Project Model
- workflow state and transition rules
- acceptance contracts
- evidence and gate state
- project memory/knowledge
- compilation into human/machine understanding
- integration capability registry
- improvement proposals and controlled overlays

## What ARTIFEX does not own

- the LLM
- the coding agent
- the research engine
- Git hosting
- CI/CD infrastructure
- sandbox implementation
- IDE functionality

## Non-goals V1

ARTIFEX V1 is not:
- a general research engine;
- a generic multi-agent framework;
- an LLM router;
- an IDE;
- a GitHub replacement;
- a CI replacement;
- a benchmark platform;
- a RAG/vector platform;
- its own coding model/agent;
- its own sandbox;
- an enterprise project-management suite.

## Greenfield and brownfield

Greenfield is represented by the normal project lifecycle.

Brownfield work uses lightweight **ChangeSets**:
Current Project Model + CHG-xxx → intent/deltas/plan/implementation/evidence → updated Project Model.

## Success test

A new developer or fresh agent, with no access to historical conversations, must be able to:
- understand the system;
- run it;
- administer it;
- modify it safely;
- validate the modification;
- continue development using only the repository.
