# ARTIFEX Codex Interface Pack

This pack makes Codex a standalone ARTIFEX interaction client and execution implementer.
Hermes is not required. Repository artifacts remain canonical; Codex sessions,
transcripts, and native memory are auxiliary.

The adapter performs distinct discovery, authentication and readiness probes plus
Git worktree inspection. Stage preparation recomputes the canonical Project Model
fingerprint as well as Git HEAD. Live execution is allowed only after public
bootstrap composition, role certification, contextual resolution and Execution
Envelope authorization; the runner result must echo the packet's base commit,
execution-contract fingerprint, and Project Model fingerprint. Missing or stale
identity fails closed. For `SUCCESS`, every claimed artifact must be inside the
packet's owned paths and must have been created or content-changed by that exact
runner invocation. The adapter rechecks canonical Project Model identity after
the runner returns. Core-authority files under `.artifex` cannot be claimed as
executor success artifacts; only `.artifex/generated/` and `.artifex/runs/` are
designated output namespaces. A governing `CHG-*` remains forbidden wherever
it is stored. Executor validation is a claim until ARTIFEX Core records evidence
and passes the applicable gate.

The `skills/` entries are Codex-facing shims for the canonical agent-neutral
skills under the repository's top-level `skills/` directory. `AGENTS.md` defines
the broad interface boundary; generated project and nested `AGENTS.md` files may
add narrower instructions without replacing canonical semantic state.

`mcp.json` uses the packaged `artifex-mcp` local stdio transport. The same semantic operations are
available through the M04 Application API and its generic CLI call surface.
