# ARTIFEX — Beginner UX and Resource Envelope

## Independent axes

Workflow depth:
- QUICK
- STANDARD
- DEEP

Experience:
- BEGINNER
- GUIDED
- EXPERT

Autonomy:
- INTERACTIVE
- ASSISTED
- AUTONOMOUS

Resource Envelope:
- optional and independent from all above.

## Beginner Mode

Beginner changes presentation, not rigor.

It should:
- use outcome language before jargon;
- recommend a default;
- expose 2–3 options only when a real trade-off exists;
- explain recommendation, gain, trade-off and reversibility;
- automatically generate full technical artifacts;
- ask only when decision risk requires it.

Risk policy example:
- LOW: ARTIFEX may decide automatically.
- MEDIUM: decide and explain/log.
- HIGH: recommend and obtain user approval in normal end-user operation.
- IRREVERSIBLE/SECURITY: explicit confirmation.

During this Codex implementation project, Project Architect escalation policy supersedes end-user UX gates.

## Resources

Separate:
1. Development resources.
2. Target runtime resources.

Constraint types:
- HARD
- SOFT

Unspecified is not unlimited.

Resource items should include provenance/confidence when relevant.

Examples:
- budget;
- CPU/RAM/GPU/storage;
- OS;
- online/offline;
- cloud/on-prem;
- existing harnesses;
- time/parallel capacity.

ARTIFEX may auto-detect local development resources and ask only for non-detectable constraints in future user-facing flows.
