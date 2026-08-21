# ARTIFEX Codex Interface Pack

This pack makes Codex a standalone ARTIFEX interface, harness, and implementer.
Hermes is not required. Repository artifacts remain canonical; Codex sessions,
transcripts, and native memory are auxiliary.

The adapter performs only read-only Codex detection (`codex --version`) and Git
worktree inspection. A caller must explicitly provide a runner/result to execute
a stage. Executor validation is a claim until ARTIFEX Core records evidence and
passes the applicable gate.

The `skills/` entries are Codex-facing shims for the canonical agent-neutral
skills under the repository's top-level `skills/` directory. `AGENTS.md` defines
the broad interface boundary; generated project and nested `AGENTS.md` files may
add narrower instructions without replacing canonical semantic state.

`mcp.json` uses the local stdio transport. The same semantic operations are
available through the M04 Application API and its generic CLI call surface.
