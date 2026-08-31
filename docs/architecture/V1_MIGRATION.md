# V1 migration authority

The ARTIFEX 2.0 migration service implements the frozen lifecycle:

`INSPECT → DRY_RUN → BASELINE/BACKUP → MIGRATE → VALIDATE → ACTIVATE`

Project Model and Git history remain semantic authority. Migration extends the
append-only Project audit but preserves the V1 model bytes, identity, accepted
semantic assets, and Git commit/tree. New semantic-revision metadata,
documentation, dashboard, reality, Catalog, and RunStore state is explicitly
classified as 2.0 bootstrap state.

The external Catalog and RunStore must remain outside the Project repository.
Migration refuses a dirty source, an already-adopted Project, reused authority
files, unsafe record paths, unsupported provider setup, and stale rollback
state. Backups include the complete pre-migration `.artifex` tree and the exact
preexisting SQLite file families.

Runtime history is intentionally empty after adoption. The first new 2.0 Run
must have exactly one Run, ProjectJob, and Attempt with `COMPLETED`, `ACCEPTED`,
and `FINISHED` states before migration activation reports `ACTIVE`.

Provider setup remains Project-owned at `.artifex/integrations.json`. If it is
absent, migration does not invent it. If a supported legacy setup is present,
its bytes are preserved and a fresh runtime loader revalidates readiness.
Credentials and prior role certification are never copied into migration
state.

The independent J09 harness imports no ARTIFEX product modules. It drives only
the installed native CLI in separate processes, clones the frozen V1 Git
commit, proves read-only planning, performs and verifies exact rollback,
reapplies migration, completes the first new Run, and emits token-free evidence
bound to the installer and installed executable.
