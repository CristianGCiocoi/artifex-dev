# Organizational Knowledge Authority

ARTIFEX 2.0 M8A introduces an Organizational Knowledge authority that is physically and
semantically separate from every Project repository. Its SQLite store owns promoted records,
recommendations, audit events, and V1 migration quarantine. It does not own Project truth.

## Authority boundary

- A Project lesson is eligible for promotion only when it is current, evidence-bound, validated,
  sufficiently confident, non-restricted, and located in its declared source Project.
- A promoted record receives a separate `ORGK-*` identity and binds the source Project revision,
  fingerprint, lesson, provenance, evidence digests, validator, promotion actor, policy, decision,
  confidence, sensitivity, applicability, and freshness horizon.
- Search applies authentication, sensitivity clearance, freshness, and explicit applicability
  filters. A recommendation receives an `ORGR-*` identity and remains advisory.
- Recommendation never writes the target Project. Adoption is an explicit authorized operation
  that revalidates the recommendation and record, creates a semantic proposal, and accepts it with
  `expected_revision` through Project Authority. The portable accepted Project model retains the
  complete lineage.
- Provider, agent, and interaction-client identities cannot exercise Knowledge Authority. There is
  no silent provider-context or cross-Project injection path.

The target Project revision and fingerprint captured by a recommendation form a CAS boundary.
Stale recommendations, direct materialization edits, dangling lessons, forged or tampered payloads,
restricted records, insufficient confidence, expired freshness, and insufficient authorization all
fail closed.

## V1 migration

V1 instance knowledge is inspected only when it is instance-scoped, current, explicitly promoted
from Project scope, bound to exactly one `project:<id>` provenance source, evidence-bound,
non-restricted, and sufficiently confident. Inspection or apply classifies the item into an isolated,
non-searchable quarantine. Migration acceptance is `N/A`; a quarantine item cannot become active
Organizational or Project Knowledge without the normal promotion, recommendation, and explicit
Project Authority adoption contracts.

## Public operations

- `knowledge.project.lesson.record`
- `knowledge.organizational.promote`
- `knowledge.organizational.search`
- `knowledge.organizational.recommend`
- `knowledge.project.adopt`
- `knowledge.migration.inspect`
- `knowledge.migration.quarantine`

All operations are shared by the CLI, Application API, and MCP operation registry. The installed-
wheel qualifier `tools/artifex2/qualify_m8a_black_box.py` executes J12 in fresh CLI processes and
proves target bytes/revision/fingerprint remain unchanged until explicit adoption, then proves
revision `+1`, lineage retention, restart continuity, and adversarial failures.
