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

## ARTIFEX 2.0 M8B public composition

The shipping CLI exposes `research pandora readiness`, `request`, `import`, and
`propose-adoption`. The same operations are present on the transport-independent
Application API as `research.pandora.*`.

The exchange root must contain a provider-written `pandora-provider.json`. It may
declare only provider `pandora`, role `RESEARCH`, and `filesystem-contract-v1`.
A valid manifest establishes contract identity, not live availability. M8B has no
independently anchored certification authority, so the shipping composition never
reports Pandora as `AVAILABLE`. Caller-supplied certification paths and hash-only
receipts are rejected explicitly; neither a fixture, a matching instance/version,
nor a locally self-issued digest can unlock readiness.

Request export and bundle import are non-canonical. Import validates path safety,
bundle/report digests, request identity, source lineage, provider instance, provider
version, and the RESEARCH role. Imported evidence does not change Project bytes,
revision, or fingerprint.

Adoption is deliberately two-step:

1. `research.pandora.adoption.propose` remains fail-closed until a future milestone
   supplies an independently anchored verifier; only then may it create a semantic
   proposal containing the complete research lineage.
2. `project.accept` performs a separate optimistic-revision acceptance through
   Project Authority.

The proposal step cannot accept itself. A caller-self-issued receipt, stale revision,
forged role, mismatched provider identity, unsafe path, or missing independent live
certification fails closed. Pandora never receives an execution role and no secret
material belongs in the Project repository or the provider manifest.

The M8B non-live qualifier builds and installs the wheel in a clean Python 3.12
environment, invokes only public CLI operations in separate processes, and proves
request/import composition plus the fail-closed adoption gate. It does not certify
J13. J13 remains blocked until a real reachable Pandora runtime completes the same
public composition and independent certification evidence is accepted.
