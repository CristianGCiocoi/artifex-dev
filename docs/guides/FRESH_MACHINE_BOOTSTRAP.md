# Fresh-Machine Bootstrap Foundation

Install a shipping ARTIFEX artifact, configure providers through the public
setup flow, then start the managed service. A new service process consumes the
persisted project-owned setup and builds the Capability Graph used by public
runtime operations.

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
