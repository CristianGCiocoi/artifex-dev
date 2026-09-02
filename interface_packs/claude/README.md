# ARTIFEX Claude Interface Pack

This optional pack exposes the canonical ARTIFEX project state to Claude Code
without making Claude, a conversation transcript, or Claude native memory part
of Core correctness.

The approval-gated setup installs the files beneath `.claude/` in a project.
The shim imports canonical, repository-owned state. Rules and skills may guide a
Claude session, but they never grant acceptance authority.

Claude Code consumes the project-scoped public `.mcp.json` mechanism. ARTIFEX
adds only the `mcpServers.artifex` entry after showing the exact mutation and
receiving explicit approval. It uses the absolute installed `artifex.exe` with
`mcp serve`, never `python -m artifex.mcp`, and records an idempotent reversible
receipt. Existing unrelated MCP servers are byte-preserved. Execution Packets
must still be bound to the selected worktree HEAD before a session is launched.
