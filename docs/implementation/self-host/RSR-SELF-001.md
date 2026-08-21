# RSR-SELF-001 — Self-host compilation impact assessment

Status: ACCEPTED
ChangeSet: CHG-SELF-001
Milestone: M11
Authority: ARTIFEX Core; no major-architecture escalation required

## Question

Can the schema-valid V1 Project Model compile complete human and machine understanding views without introducing a second source of truth?

## Observed gap

The canonical `ProjectModel` and `project-model.schema.json` expose `project`, `git`, `artifacts`, and `entities`. The M03 compiler also accepts a richer mapping vocabulary such as `architecture`, `workflows`, `capabilities`, `interfaces`, and `invariants`. Existing compiler tests exercise that richer mapping directly, but a schema-valid canonical Project Model cannot contain those extra top-level fields.

For ARTIFEX's self-model, compiling the canonical JSON directly therefore preserves identity and artifacts but leaves most understanding and comprehension topics empty. Copying the same meaning into an ad-hoc compiler input would create an ungoverned duplicate truth.

## Selected approach

Add a deterministic, side-effect-free Compilation Layer projection:

- retain the canonical Project Model as the fingerprinted source;
- accept understanding statements only from `metadata.understanding` on `ACCEPTED` artifacts;
- derive typed entity collections in stable ID order;
- allow only the documented compiler vocabulary;
- fail closed when accepted artifacts define conflicting values for the same understanding field;
- preserve compatibility for existing rich mapping callers;
- keep every compiled output explicitly non-canonical and bound to the raw Project Model fingerprint.

The ARTIFEX self-model uses `ART-SELF-CHARTER` as the accepted semantic source for the reserved `metadata.understanding` namespace. Requirements, invariants, capabilities, interfaces, milestones, and tasks remain separately available as typed entities for traceability.

## Impact

Affected implementation surfaces are limited to the Compilation Layer projection and its human, machine, packet, dashboard, and comprehension entry points. Project Model schema, Core authority, workflow transitions, integration selection, vendor configuration, and accepted architecture/invariant documents do not change.

Generated self-documentation is written only beneath `.artifex/generated/understanding/` during M11 orchestration. It must not overwrite accepted source documents under `docs/architecture`, `docs/requirements`, or `docs/implementation/milestones`.

## Risks and controls

- Conflicting metadata could make projection order-dependent. Control: sort by stable artifact ID and reject unequal duplicate values.
- Non-accepted content could influence generated views. Control: ignore all artifact statuses except `ACCEPTED`.
- A projection could obscure provenance. Control: generation manifests continue to fingerprint the unmodified canonical Project Model.
- Rich legacy callers could regress. Control: preserve existing top-level values and run the complete M03 compiler/comprehension suite.
- Generated views could be mistaken for authority. Control: retain generated/non-canonical banners and freshness manifests.

## Alternatives rejected

- Expanding the V1 Project Model schema with compiler-specific top-level fields: unnecessary Core schema and architecture change.
- Parsing arbitrary repository Markdown at compilation time: ambiguous authority and duplicate-ID behavior.
- Maintaining a separate rich compiler JSON file: duplicate canonical meaning and freshness risk.

## Rollback

Revert the projection implementation and its tests, remove generated outputs, and continue using the existing rich-mapping compiler API. The canonical Project Model, accepted source documents, and audit history remain valid and unchanged.
