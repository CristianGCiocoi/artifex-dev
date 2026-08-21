---
name: artifex
description: Execute a narrow ARTIFEX stage from portable canonical project state.
---

# ARTIFEX execution skill

1. Read the root `CLAUDE.md` shim and the supplied Execution Packet.
2. Verify the selected Git worktree HEAD equals the packet `base_commit`.
3. Work only in packet-owned paths and preserve listed interfaces and invariants.
4. Run the packet acceptance checks without invoking unrelated live or destructive work.
5. Return a structured executor claim with status, artifacts, validation, message,
   `base_commit`, `execution_contract_fingerprint`, and `project_model_fingerprint` copied
   exactly from the packet. Never invent or omit result identity.
6. Claim only owned files that this invocation actually created or content-changed.
   Do not claim the canonical Project Model or governing ChangeSet as output.

Claude never transitions project acceptance. When the worktree or project
fingerprint has drifted, return `REBASE_REQUIRED`; when authority or required
input is missing, return `BLOCKED`.
