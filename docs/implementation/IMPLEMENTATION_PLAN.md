# ARTIFEX — Implementation Plan v1.0 — ACCEPTED

## Milestones

- **M0** Bootstrap & Architecture Contracts
- **M1** Project Model & Git Store
- **M2** Workflow & Validation Core
- **M3** Compilation & Understanding
- **M4** Integration Foundation
- **M5** Hermes Preferred Integration
- **M6** Codex Standalone
- **M7** Claude Standalone
- **M8** Knowledge & Controlled Evolution
- **M9** Beginner Mode & Distribution
- **M10** Optional Providers — DeepSeek + Pandora
- **M11** Self-hosting & V1 Release

## Dependency shape

M0 → M1.
M1 enables M2 and M3.
M2+M3 → M4.
M4 → M5/M6/M7.
M8 Core work may begin after M1+M2 and completes with integration evidence later.
M9 depends on stable M5/M6/M7 integration behavior.
M10 may begin after M4 and does not block Core V1 GA.
M11 depends on Core path M0–M9, not on optional M10.

## Milestone states

PLANNED → READY → ACTIVE → IMPLEMENTED → VERIFYING → ACCEPTED.
BLOCKED and SUPERSEDED are explicit alternate states.

## Acceptance rule

A milestone is ACCEPTED only if:
- all mandatory task gates pass;
- milestone integration gate passes;
- traceability is current;
- no critical blocker remains;
- acceptance evidence is current;
- relevant documentation is current;
- architecture gate passes where required;
- understanding gate passes from M3 onward where relevant.

Routine milestone acceptance is autonomous when defined evidence passes.

## Release gate

V1 GA requires:
- BUILD PASS
- VALIDATION PASS
- UNDERSTANDING PASS
- CONTINUITY PASS
- PORTABILITY PASS
- PACKAGING PASS
- SELF-HOST PASS
- Hermes preferred path PASS
- Codex standalone PASS
- Claude standalone PASS
- Manual fallback PASS

Optional DeepSeek/Pandora packs do not block Core GA.
