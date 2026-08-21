# ARTIFEX — Validation, Evidence and Gate Specification

## Core rule

Executor completion is a claim. Canonical acceptance is derived by ARTIFEX from contracts, evidence, waivers and gate policy.

## Acceptance Contract

Each executable task/stage/milestone defines:
- immutable ID;
- deliverable;
- applicable requirements;
- relevant interfaces/invariants;
- acceptance criteria;
- validators;
- base commit/model fingerprint at execution start;
- contract hash.

After execution starts, criteria cannot be silently weakened. Legitimate change requires a new contract version/change event and invalidates affected evidence.

## Validator preference order

1. deterministic validator;
2. structured inspection;
3. fresh independent agent evaluation;
4. explicit human validation.

Use model judgment only when a cheaper/more deterministic mechanism cannot answer reliably.

## Evidence Ledger

Evidence entry includes:
- EVD ID;
- validator identity/version;
- claim tested;
- result;
- measured facts;
- base commit;
- contract hash;
- relevant Project Model fingerprints;
- minimized/scrubbed evidence output;
- timestamp.

## Gate states

PENDING / PASS / FAIL / BLOCKED / WAIVED / STALE.

## Gate hierarchy

Task Gate → Integration Gate → Milestone Gate → Release Gate.

All child task gates passing does not imply integration/milestone pass.

## Waiver

Executor may request; executor may not self-approve.

Waiver includes:
- WAV ID;
- gate;
- reason;
- impact;
- requested_by;
- authority;
- expiry/revisit condition.

## Staleness

A passed gate/evidence becomes STALE when a relevant verified input changes and the validator cannot prove the change is irrelevant.

## Command validation security

Do not model checks as arbitrary shell strings by default. Prefer typed validators with argv, cwd, timeout, expected exit/status/schema and explicit permission/sandbox policy.

## Metrics

Dashboard/report counts must be recomputed from current evidence at report generation time.
