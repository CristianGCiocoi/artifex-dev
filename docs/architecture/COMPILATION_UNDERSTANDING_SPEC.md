# ARTIFEX — Compilation and Understanding

## Principle

Human and machine documentation are views of one Canonical Project Model. Do not maintain duplicate independent truths.

## Context Packet

Contains minimum sufficient context for reasoning.

## Execution Packet

Context Packet +
- task;
- acceptance contract;
- relevant interfaces/invariants;
- ownership;
- permissions;
- expected output.

## Human Understanding outputs

STANDARD/DEEP projects should support:
- README
- USER_GUIDE
- ADMIN_GUIDE
- DEVELOPER_GUIDE
- CONCEPTS
- ARCHITECTURE
- WORKFLOWS
- CAPABILITIES
- INVARIANTS
- EXTENSION_GUIDE
- SECURITY
- RUNBOOK when applicable
- UPGRADE
- KNOWN_LIMITATIONS
- PROJECT_HISTORY
- IMPLEMENTATION_STATUS/DASHBOARD
- optional PAPER when eligible.

## Machine Understanding outputs

- project manifest
- architecture/capability/interface/invariant maps
- validation rules
- context index
- AGENTS.md
- CLAUDE.md
- integration-specific skill/context shims.

Vendor-specific files are generated views.

## Staleness

Generated artifact stores source fingerprints. Source changes cause CURRENT→STALE until recompiled/revalidated.

## Comprehension Gate

Fresh-context evaluator, with repository only, must correctly identify:
- purpose;
- architecture;
- core components;
- important workflows;
- invariants;
- how to run/administer/test;
- extension points;
- known limitations;
- current implementation state.

No conversation history may be required.
