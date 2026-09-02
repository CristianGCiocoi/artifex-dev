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

The setup flow installs the `skills/` entries under the current Codex repository
layout, `.agents/skills/artifex-*/SKILL.md`. It adds a bounded managed section to
the repository `AGENTS.md`; existing instructions remain untouched.

Current Codex MCP registration is in `~/.codex/config.toml`. ARTIFEX previews the
exact block, requires an explicit single-use approval, and writes a secret-free
receipt before reporting readiness. The command is the absolute installed
`artifex.exe` path with `mcp serve`; it does not depend on PATH or a Python module.
`config.toml.example` documents the generated shape. `mcp.json` is retained only
as a portable legacy descriptor and is not the public Codex configuration source.

Use `artifex client doctor codex ...` for bounded version, registration, bridge,
and file checks. It never invokes a model or changes PowerShell ExecutionPolicy.
