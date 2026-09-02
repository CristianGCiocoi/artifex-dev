# ARTIFEX Windows Quick Start

This is the normal, non-terminal path for ARTIFEX 2.0.2.

1. Open the downloaded `ARTIFEX-Setup.exe` and complete installation. The
   installer does not report readiness until the managed service is healthy.
2. Leave **Launch ARTIFEX** selected, or open **ARTIFEX** from the Windows Start
   menu. The authenticated local Platform Dashboard opens in your browser.
3. Review the installed version, managed-service status and canonical state
   location shown at the top. Resolve any **Action needed** item before adding
   provider integrations.
4. Choose **Add Project** for a new location or **Import Project** for an
   existing repository. ARTIFEX sends this through Project Authority; the
   dashboard is not a separate source of project truth.
5. Open the Project card and choose **Open Project Dashboard**.
6. On the Codex or Claude card, choose **Review setup**. Read the exact planned
   configuration changes and rollback description. Nothing changes until you
   choose **Approve and apply**.
7. Open **Diagnostics** to confirm the client, bridge, service, state root and
   receipt readiness. Then start a fresh provider conversation and perform a
   read-only ARTIFEX operation.

ARTIFEX does not require manual PATH editing for this flow. Never weaken
PowerShell execution policy, paste provider tokens into a Project, or hand-edit
vendor configuration to turn a failed readiness check green.

The Platform Dashboard is the installed product UI. The implementation
dashboard is release-engineering evidence and is not used to manage Projects.

See [provider onboarding and troubleshooting](PROVIDER_ONBOARDING.md) for
client-specific checks and recovery guidance.
