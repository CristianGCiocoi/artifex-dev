# Fresh-Machine Bootstrap Foundation

Install a shipping ARTIFEX artifact. The installer starts the managed service
and does not report readiness until the health gate passes. Launch ARTIFEX from
the Start menu, then add/import a Project and configure providers through the
approval-gated Platform Dashboard. A new service process consumes the
persisted project-owned setup and builds the Capability Graph used by public
runtime operations.

The normal Windows journey is non-CLI; see
[Windows Quick Start](QUICK_START_WINDOWS.md). The commands below are optional
administrator diagnostics, not required user remediation:

Use these public checks after the service starts:

```text
artifex service status
artifex bootstrap --project-root PROJECT
artifex doctor --project-root PROJECT
```

If no certified automated provider is ready, bootstrap returns
`MANUAL_FALLBACK`. The response explains how to create a portable manual packet
and submit its result for validation. A manual result is a claim and never
self-accepts.

Provider configuration being present is not readiness. A provider becomes an
automated candidate only when a fresh runtime loads its setup, observes live
readiness, and finds an independently certified mandatory role. Contextual
dispatch still requires the Resolver, Execution Envelope, scoped actor and
credential references, and separate Acceptance Authority.

The current foundation has been black-box verified from an installed wheel.
Full J01 and J02 acceptance awaits an approved product support matrix and live
qualification on every declared applicable cell. The observed development
host is not implicitly a supported platform.
