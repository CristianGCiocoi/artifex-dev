# ARTIFEX Upgrade Guide

Candidate: 9189765d392c2e03db81056e05da64e060097652

Model: 82364730319cfe057f28cb6b2a6482a5e298c86b76fb4da2867e14754f43d76d

## Purpose

This upgrade guide explains upgrade compatibility, authenticated backup, atomic activation, and rollback. ARTIFEX keeps repository and Git state canonical while generated narrative remains inspectable but non-canonical. The document connects upgrade, compatibility, and rollback to version 1.0.0 without presenting a build as release authority. Its component context includes Project Model and Git Store, Workflow Engine, Validation and Evidence, Compilation and Understanding, Integration Registry, Knowledge and Controlled Evolution, Distribution and Beginner Experience, Application API, CLI, and MCP.

## Authority

ARTIFEX Core alone evaluates acceptance for this upgrade guide. Immutable contracts bind the exact source commit, Project Model fingerprint, validator registry, and evidence scope before any promotion. Executors and integrations may report results, but their claims cannot alter canonical state. Human, architecture, or policy gates remain explicit when required, and external content is always treated as untrusted data rather than instructions.

## Controls

The rollback control path fails closed on stale commits, mismatched hashes, duplicate identities, unsafe paths, unexpected files, missing measurements, or privilege expansion. Evidence is secret-safe, append-only, independently produced, and tied to the frozen candidate. Replaceable providers preserve the same semantic API, while rollback and recovery remain explicit rather than silently rewriting history.

## Verification

Verification for this upgrade guide replays deterministic checks, validates typed schemas, compares package inventories to candidate S, and checks upgrade results across Linux, Windows, and macOS. Independent review confirms compatibility boundaries, the comprehension result, audit ordering, traceability, and all nonwaivable gates. The current source is a candidate until the release verifier returns PASS and Core records the promotion; publisher signing and notarization are not claimed in V1.
