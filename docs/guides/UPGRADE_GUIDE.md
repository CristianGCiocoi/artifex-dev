# ARTIFEX V1 to 2.0 Upgrade Guide

ARTIFEX 2.0 adopts an existing V1 Project without rewriting Git history or
inventing historical runtime activity. The supported Windows path uses the
installed shipping executable and keeps the Project repository separate from
the instance Catalog, RunStore, approval records, and migration backups.

## Before migration

Use a clean V1 Git worktree and choose new external paths for the Catalog and
RunStore. Keep the migration state directory on storage covered by the normal
backup policy. Provider authentication remains provider-owned; ARTIFEX never
copies credentials into the Project or migration record.

First inspect, then request the dry-run plan:

```console
artifex migration inspect --project-root C:\Projects\example --catalog C:\ProgramData\ARTIFEX\catalog.sqlite3 --runstore C:\ProgramData\ARTIFEX\runstore.sqlite3 --state-root C:\ProgramData\ARTIFEX\migrations
artifex migration plan --project-root C:\Projects\example --catalog C:\ProgramData\ARTIFEX\catalog.sqlite3 --runstore C:\ProgramData\ARTIFEX\runstore.sqlite3 --state-root C:\ProgramData\ARTIFEX\migrations
```

Inspection and planning are read-only. The plan reports the exact effects,
rollback path, fingerprint, and a short-lived single-use confirmation token.

## Apply and validate

Apply only the token from the unchanged plan:

```console
artifex migration apply --project-root C:\Projects\example --catalog C:\ProgramData\ARTIFEX\catalog.sqlite3 --runstore C:\ProgramData\ARTIFEX\runstore.sqlite3 --state-root C:\ProgramData\ARTIFEX\migrations --confirm <confirmation-token>
```

The operation creates a verified backup before mutation, accepts the first
2.0 Project Authority revision, registers the stable Project ID, generates
current documentation and dashboard projections, and initializes an empty
RunStore. Existing provider setup is preserved and consumed by a fresh
readiness loader; no provider certification is copied forward.

The returned migration record path can be checked at any time:

```console
artifex migration validate --record <record-path> --project-root C:\Projects\example --catalog C:\ProgramData\ARTIFEX\catalog.sqlite3 --runstore C:\ProgramData\ARTIFEX\runstore.sqlite3 --state-root C:\ProgramData\ARTIFEX\migrations
```

Activation remains pending until exactly one new 2.0 Run finishes and is
accepted. V1 activity is never converted into Runs, ProjectJobs, Attempts,
leases, workspaces, scheduler decisions, or provider runtime events.

## Rollback

Rollback is separately planned and approved:

```console
artifex migration rollback-plan --record <record-path> --project-root C:\Projects\example --catalog C:\ProgramData\ARTIFEX\catalog.sqlite3 --runstore C:\ProgramData\ARTIFEX\runstore.sqlite3 --state-root C:\ProgramData\ARTIFEX\migrations
artifex migration rollback --record <record-path> --project-root C:\Projects\example --catalog C:\ProgramData\ARTIFEX\catalog.sqlite3 --runstore C:\ProgramData\ARTIFEX\runstore.sqlite3 --state-root C:\ProgramData\ARTIFEX\migrations --confirm <rollback-token>
```

Rollback is allowed only while the Project bootstrap state, Catalog, and
RunStore still match the recorded post-migration state. If a new Run or other
state change exists, ARTIFEX refuses rollback rather than discarding it.

## Authority and evidence

The Project repository and Git remain semantic authority. The migration record
contains pre/post fingerprints, the preserved/extended/added asset inventory,
bootstrap actions, empty-history proof, provider readiness disposition,
backup digest, validation checks, and rollback reference. J09 acceptance must
be reproduced with the native shipping candidate and a real copy of the V1
release; source-only or developer-only execution is not release evidence.
