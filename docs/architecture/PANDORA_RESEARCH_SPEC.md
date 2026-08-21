# ARTIFEX — Pandora Research Integration

## Boundary

Pandora and ARTIFEX remain separate projects.

ARTIFEX asks:
"What research evidence is needed to make this software-development decision?"

Pandora may answer:
"Here is source-backed research and evidence."

ARTIFEX alone owns the canonical project decision.

## Integration role

Pandora advertises:
`research_provider: true`

It is:
- optional;
- replaceable;
- never imported by Core;
- never the only way to perform research.

## Core contracts

### ResearchRequest

Includes:
- request ID;
- purpose/stage;
- questions;
- project constraints;
- required freshness/source-quality;
- resource envelope;
- desired alternatives/risks/output form.

### ResearchBundle

Includes:
- bundle ID;
- findings;
- alternatives;
- claim/evidence/confidence structures;
- unresolved questions;
- source manifest;
- generation metadata.

## Initial transport

V1 may use filesystem:
`research-request.yaml` → Pandora → `research-bundle.json` + `research-report.md`.

Future CLI/MCP/API transport must preserve the semantic contract.

## Policy

QUICK: native research.
STANDARD: native by default, escalate to Pandora when depth/evidence needs justify it.
DEEP: Pandora preferred when available for deep external research.

Pandora must not modify ARTIFEX Project Model directly.
