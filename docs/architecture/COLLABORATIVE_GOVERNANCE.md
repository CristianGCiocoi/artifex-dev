# Collaborative Lifecycle and Operational Governance

ARTIFEX 2.0 represents each frontend connection as a durable, frontend-neutral
`InteractionSession`. A session belongs to a Project, may optionally attach to a
Workstream and Run, records its actor/delegation, and can disconnect and reconnect
without becoming Project authority. Reconnect credentials are stored only as hashes
in the RunStore and are never written to Project Git.

Semantic collaboration remains optimistic. Each session submits against the semantic
revision it last observed. Project Authority is the sole acceptance path. A stale
session receives a revision conflict and must refresh or reconcile; ARTIFEX never uses
last-write-wins for accepted semantics.

The first-half lifecycle is represented in the portable Project Model:

`IDEA -> EXPLORATION -> RESEARCH -> DEFINITION -> ARCHITECTURE -> REQUIREMENTS_ADRS -> PLAN -> ENVELOPE_PROPOSED -> APPROVED_PLAN`

Each lifecycle contribution records the interaction actor, session, evidence and
decision references. The default IDEA state is omitted from serialization until the
first M4 contribution, preserving the exact M1 representation and fingerprints of
existing Projects. Advancing a stage creates and accepts an ordinary optimistic
semantic revision through Project Authority.

An Execution Envelope is proposed before it can be approved. Proposal and approval
are separate durable RunStore events. Only an authenticated authorized actor may
approve; interaction clients, providers and automation cannot approve. Run
authorization consumes the previously approved immutable Envelope and creates a
PENDING Attempt. Authorization is not dispatch.

Strategic/material work creates a durable `DecisionRequest`. Creation atomically
blocks only the affected Workstreams. Unrelated authorized Workstreams continue.
While blocked, the affected ProjectJob cannot be accepted or promoted. Only a USER
with resolution authority may approve the decision and resume those Workstreams.

Operational control uses `RUNNING`, `DRAINING`, `PAUSED`, and `EMERGENCY_STOP` at
Platform, Project, Workstream, Run, ProjectJob, and Platform-wide provider scope. The most
restrictive applicable state governs a dispatch. DRAINING and PAUSED block new
dispatch but retain RunStore, audit, read, control, and recovery access. An
unconfirmed emergency termination never becomes a false stop claim: the Attempt
transitions to `NEEDS_RECONCILIATION`. Clearing EMERGENCY_STOP requires an explicit
reconciled assertion.

Public operations:

- `interaction.open`, `interaction.disconnect`, `interaction.reconnect`,
  `interaction.close`, `interaction.list`
- `interaction.semantic.submit`, `interaction.lifecycle.advance`
- `governance.decision.request`, `governance.decision.resolve`
- `governance.envelope.propose`, `governance.envelope.approve`
- `control.set`, `control.status`
- `runtime.run.authorize`

The installed-wheel black-box qualifier is
`tools/artifex2/qualify_m4_black_box.py`. It exercises J04, J06, J07 and J19 only
through fresh public CLI processes.
