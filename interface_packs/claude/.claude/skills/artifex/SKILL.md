---
name: artifex
description: Execute a narrow ARTIFEX stage from portable canonical project state.
---

# ARTIFEX execution skill

1. Read the root `CLAUDE.md` shim and the supplied Execution Packet.
2. Verify the selected Git worktree HEAD equals the packet `base_commit`.
3. Work only in packet-owned paths and preserve listed interfaces and invariants.
4. Run the packet acceptance checks without invoking unrelated live or destructive work.
5. Return a structured executor claim with status, artifacts, validation, and message.

Claude never transitions project acceptance. When the worktree or project
fingerprint has drifted, return `REBASE_REQUIRED`; when authority or required
input is missing, return `BLOCKED`.
