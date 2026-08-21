# M1 — Project Model & Git Store

## Goal
Make repository artifacts + Git the canonical semantic truth.

## Tasks

- **M1-T01 Init/adopt:** greenfield initialization and safe brownfield adoption.
- **M1-T02 Git baseline:** detect/init Git, `main`, baseline SHA, dirty-state policy, remote metadata.
- **M1-T03 Artifact parser/index:** parse Markdown/front matter + YAML/JSON structured artifacts; stable IDs.
- **M1-T04 Project Model structured entities:** requirements, assumptions, constraints, capabilities, interfaces, invariants.
- **M1-T05 Dependency graph/staleness:** artifact dependency graph and STALE propagation.
- **M1-T06 External edit reconciliation:** detect content fingerprint changes outside Application API and create reconciliation event.
- **M1-T07 ChangeSet lifecycle:** PROPOSED→ACCEPTED→IMPLEMENTING→VERIFIED→APPLIED→ARCHIVED lightweight semantics.
- **M1-T08 Audit history:** append-only significant events JSONL.
- **M1-T09 Git-backed provenance:** bind artifact/version events to commit where available.
- **M1-T10 ProjectStore hardening:** atomic writes, corruption/missing semantics, path normalization and cross-platform tests.

## Parallelism
T01/T02 foundation first. T03/T04/T10 can parallelize after store skeleton. T05/T06 depend on fingerprints/index. T07/T08/T09 after core model.

## Gates
SCHEMA + PROPERTY + GIT + STALENESS + EXTERNAL-EDIT + CHANGESET + CROSS-PLATFORM path behavior.
