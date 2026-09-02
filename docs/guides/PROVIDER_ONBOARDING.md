# Provider onboarding and troubleshooting

## Shared approval model

Codex and Claude use the installed standalone ARTIFEX MCP bridge. Select the
Project in Platform Dashboard, choose the provider's **Review setup** action,
and inspect the exact files/settings to be changed, their prior values, client
version and rollback plan. **Cancel** leaves vendor configuration unchanged.
**Approve and apply** records the approval, applies the plan, verifies the
bridge and preserves a rollback receipt.

Do not add provider secrets to Project Git. ARTIFEX stores references and
readiness facts, not copied authentication tokens. A provider being detected
is not the same as being configured, authenticated, verified, or certified for
a role; the dashboard and diagnostics report these states separately.

## Codex

Codex Desktop and the Codex CLI are separate client forms. A working desktop
application does not prove that `codex` is available to an integration. The
setup review shows the detected form and version and uses the current supported
Codex MCP/configuration layout. If the supported path needs the CLI and it is
absent, install/authenticate it using the official client flow, then retry the
dashboard verification. Do not edit PATH or PowerShell execution policy as a
repair.

## Claude

Claude setup uses the public Claude MCP configuration mechanism and points to
the installed standalone ARTIFEX bridge. It does not depend on a source
checkout or `python -m artifex.mcp`. Authenticate Claude through its own client
flow, then return to Platform Dashboard and rerun verification.

## Troubleshooting

- **Client not detected:** confirm that the intended client form is installed
  for the current Windows user. Reopen Platform Dashboard and review setup.
- **Installed but not authenticated:** authenticate in the provider's own UI.
  ARTIFEX must not collect the credential.
- **Bridge not callable:** open **Diagnostics** and check installation integrity,
  the managed service, canonical state root and MCP bridge. Use the proposed
  repair; do not substitute a Python module from a checkout.
- **Configuration differs:** cancel, inspect the displayed previous/current
  values and export diagnostics. Reapply only from a new approval plan.
- **Provider available but integration not ready:** availability, configuration,
  authentication, live verification and role certification are separate facts.
- **Hermes shown as absent:** Hermes is optional and should read **Optional / not
  configured** unless explicitly activated; it is not a Core onboarding error.
- **Unexpected error:** preserve the concise diagnosis and diagnostic export.
  Raw tracebacks and secret-bearing configuration should not be shared.

Rollback uses the receipt created by the approved change. It restores only the
settings owned by that plan and does not rewrite unrelated vendor state.
