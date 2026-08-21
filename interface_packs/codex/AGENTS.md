# ARTIFEX Codex standalone instructions

Use the repository Project Model, accepted architecture, task/acceptance
contracts, evidence, and gates as instruction authority. Read the effective
`AGENTS.md` hierarchy from repository root toward the owned target; a deeper
file narrows its directory scope and `AGENTS.override.md` wins within one
directory.

Use the smallest relevant skill in `interface_packs/codex/skills/`. Those files
route to agent-neutral ARTIFEX semantics and do not create vendor-owned truth.

Bind every worker to the Execution Packet base commit, contract fingerprint,
Project Model fingerprint, ownership, and acceptance criteria. Recompute Git
HEAD and the canonical Project Model fingerprint before execution. Require raw
harness results to echo all three binding fields; missing identity fails closed
and stale identity is `REBASE_REQUIRED`. Never infer canonical acceptance from
a Codex success or validation claim.

Native Codex memory and parent transcripts are auxiliary. Continuity must be
reconstructable from repository artifacts alone. Do not start live mutating
Codex execution from a detection or conformance probe.
