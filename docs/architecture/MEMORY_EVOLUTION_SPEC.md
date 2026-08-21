# ARTIFEX — Memory and Controlled Evolution

## Scopes

CORE → PROFILE → INSTANCE → PROJECT → RUN → HARNESS

V1 fully implements primarily PROJECT, INSTANCE and RUN semantics.
HARNESS memory is auxiliary only.

## Memory kinds

- FACT
- ASSUMPTION
- DECISION
- PREFERENCE
- LESSON
- PATTERN

Each important item should contain:
- stable ID;
- scope;
- statement;
- provenance;
- confidence;
- sensitivity/promotion policy;
- verified-against metadata when applicable;
- revisit triggers.

## Promotion

RUN/HARNESS finding
→ candidate
→ PROJECT
→ repeated/validated
→ INSTANCE

V1 stops automatic promotion at INSTANCE.

PROFILE/UPSTREAM promotion is modeled but becomes a fuller V2 capability.

## Self-improvement

Observation → LESSON → IMPROVEMENT PROPOSAL → CANDIDATE OVERLAY.

Never modify installed Core directly.

Candidate overlay must include:
- origin Core version;
- reason/evidence;
- target component/skill/workflow;
- expected benefit;
- compatibility;
- validation status.

## Update compatibility

Future update replays local overlays and classifies:
- CARRY_FORWARD
- SUPERSEDED
- REVALIDATE
- CONFLICT

Activation is atomic after validation.

## Privilege ceiling

A methodology/skill/workflow improvement cannot autonomously expand execution permissions or security authority.
