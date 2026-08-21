# ARTIFEX Claude Interface Pack

This optional pack exposes the canonical ARTIFEX project state to Claude Code
without making Claude, a conversation transcript, or Claude native memory part
of Core correctness.

Install the files beneath `.claude/` in a project and use `CLAUDE.md` as the
project-root shim. The shim imports canonical, repository-owned state. Rules and
skills may guide a Claude session, but they never grant acceptance authority.

The MCP entry is optional and local-stdio only. Generate or copy it explicitly;
the adapter never edits Claude Desktop configuration. Execution Packets must be
bound to the selected worktree HEAD before a session is launched.
