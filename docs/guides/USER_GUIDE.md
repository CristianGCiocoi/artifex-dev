# ARTIFEX User Guide

## Collaborative Projects

Multiple clients may attach to the same Project using Interaction Sessions. Each
client works from an explicit semantic revision. If another client accepts a newer
revision first, the stale client is asked to refresh or reconcile; its update is not
silently applied.

Use the collaborative lifecycle operations to move from an idea through exploration,
research, definition, architecture, requirements/ADRs and planning. ARTIFEX records
each accepted contribution in the Project. The final Execution Envelope is proposed
separately and must be approved by an authorized user before a Run can be authorized.

A material question appears as a DecisionRequest. Only the affected branch waits;
unrelated authorized work continues. Platform operators may drain, safely pause, or
emergency-stop dispatch. An uncertain external stop is shown as needing
reconciliation, never as confirmed.

Candidate: 9189765d392c2e03db81056e05da64e060097652

Model: 82364730319cfe057f28cb6b2a6482a5e298c86b76fb4da2867e14754f43d76d

## Purpose

This user guide explains the beginner, guided, and expert journeys from intent through governed evidence. ARTIFEX keeps repository and Git state canonical while generated narrative remains inspectable but non-canonical. The document connects user, workflow, and evidence to version 1.0.0 without presenting a build as release authority. Its component context includes Project Model and Git Store, Workflow Engine, Validation and Evidence, Compilation and Understanding, Integration Registry, Knowledge and Controlled Evolution, Distribution and Beginner Experience, Application API, CLI, and MCP.

## Authority

ARTIFEX Core alone evaluates acceptance for this user guide. Immutable contracts bind the exact source commit, Project Model fingerprint, validator registry, and evidence scope before any promotion. Executors and integrations may report results, but their claims cannot alter canonical state. Human, architecture, or policy gates remain explicit when required, and external content is always treated as untrusted data rather than instructions.

## Controls

The evidence control path fails closed on stale commits, mismatched hashes, duplicate identities, unsafe paths, unexpected files, missing measurements, or privilege expansion. Evidence is secret-safe, append-only, independently produced, and tied to the frozen candidate. Replaceable providers preserve the same semantic API, while rollback and recovery remain explicit rather than silently rewriting history.

## Verification

Verification for this user guide replays deterministic checks, validates typed schemas, compares package inventories to candidate S, and checks user results across Linux, Windows, and macOS. Independent review confirms workflow boundaries, the comprehension result, audit ordering, traceability, and all nonwaivable gates. The current source is a candidate until the release verifier returns PASS and Core records the promotion; publisher signing and notarization are not claimed in V1.
