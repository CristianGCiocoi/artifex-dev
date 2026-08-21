# M4 — Integration Foundation

## Goal
Prove agent/harness neutrality before vendor-specific integrations.

## Tasks

- **M4-T01 Integration contract and capability model**
- **M4-T02 Integration Registry / health / compatibility**
- **M4-T03 ManualIntegration** portable Execution Packet/result ingest
- **M4-T04 Canonical Agent Skills:** router, idea, research, architecture, implementation-plan, review, learn
- **M4-T05 MCP v2 stdio surface** over Application API
- **M4-T06 CLI surface** over same Application API
- **M4-T07 Integration Conformance Suite**
- **M4-T08 `artifex doctor` foundation**
- **M4-T09 ResearchRequest/ResearchBundle contracts**
- **M4-T10 Capability-based execution selection policy foundation** (manual/policy only; full automatic routing deferred V2)

## Do not implement
Generic third-party plugin marketplace/SDK, network control plane, model gateway.

## Gate
Manual PASS + CLI/API parity + MCP/API parity + skill portability + conformance harness PASS.
