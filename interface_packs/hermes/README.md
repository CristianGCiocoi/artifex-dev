# ARTIFEX Hermes Interface Pack

This pack connects a Hermes session to ARTIFEX through the public CLI or local
stdio MCP surface. It is an interface view, not canonical project state.

Install it only through `HermesIntegration.install_interface_pack(...)`. The
installer verifies the manifest allowlist and hashes and writes to an explicit
target. Detection and normal adapter construction never install or modify
Hermes.

The skill requires repository-backed `.artifex` state, execution packets, and
Core-owned validation. Hermes conversation history and native memory remain
auxiliary and disposable.
