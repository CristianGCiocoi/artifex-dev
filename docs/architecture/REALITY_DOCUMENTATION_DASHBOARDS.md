# Reality, Documentation, and Operational Dashboards

ARTIFEX separates accepted Project intent from observed external state and from
generated views.

## Authority boundaries

- Project Authority remains the only path that accepts a semantic revision.
- Observers append sourced facts to the Project Observation Store. A mismatch
  creates an explicit Divergence and may create a semantic proposal, but it
  never changes the accepted revision.
- Project documentation is generated from an accepted semantic revision. Its
  manifest and rendered files are rebuildable projections, not Project truth.
- Project and Platform dashboards are rebuilt from Project Authority, Project
  Catalog, documentation lifecycle, and Observation Store state. Editing a
  dashboard cannot change any of those stores.

The supported observer vocabulary is `GIT`, `FILE`, `TEST`, `PROVIDER`,
`RUNTIME`, and `SERVICE`. The built-in repository reconciliation reads the real
portable Project Model. Git/file observers read bounded local state; provider,
test, runtime, and service integrations implement the same sourced observer
interface.

## Documentation lifecycle

Every created or adopted Project receives a documentation baseline in
`.artifex/docs/` and a non-authoritative lifecycle manifest at
`.artifex/docs/manifest.json`.

After Project Authority accepts a change, ARTIFEX compares each document's
declared semantic inputs. Only affected documents become `STALE`. Regeneration
can target named documents or, with no target, all `STALE`/`MISSING` documents.
A document becomes `CURRENT` only after it is rendered, written, and its content
and source fingerprints validate against the accepted revision.

## Public operations

All operations are available through the shared Application API, generic
`artifex call` transport, and dedicated CLI groups:

```text
project.observe
reality.state
documentation.status
documentation.regenerate
dashboard.project
dashboard.platform
```

Examples:

```powershell
artifex project observe "My Project" --catalog C:\path\catalog.sqlite3
artifex reality state "My Project" --catalog C:\path\catalog.sqlite3
artifex documentation status "My Project" --catalog C:\path\catalog.sqlite3
artifex documentation regenerate "My Project" --document ARCHITECTURE.md --catalog C:\path\catalog.sqlite3
artifex dashboard project "My Project" --catalog C:\path\catalog.sqlite3
artifex dashboard platform --catalog C:\path\catalog.sqlite3
```

`project observe` is deliberately reconciliation input, not an acceptance
command. Review any returned proposal and use the normal `project accept`
authority path if the external change is intended.
