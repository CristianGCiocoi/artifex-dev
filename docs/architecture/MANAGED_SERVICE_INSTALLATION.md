# ARTIFEX Managed Service and Installation Foundation

ARTIFEX hosts durable runtime authority independently of CLI, MCP, or other
frontend lifetimes. The managed service owns one SQLite RunStore, one current
coordinator generation, and its Execution Workspaces under a user-scoped state
root. Project semantic authority remains in each Project repository.

The public host entrypoints are:

```text
artifex service serve [--state-root PATH]
python -m artifex.managed_service [--state-root PATH]
```

The public frontend commands are:

```text
artifex service status [--state-root PATH]
artifex service call OPERATION --arguments JSON [--project-root PATH]
artifex service stop [--state-root PATH]
```

Transport is authenticated JSONL v1 over IPv4 loopback, bounded to 1 MiB per
request. The transport token is a private file separate from the secret-free
`service-state.json` projection. A second host fails closed while the live
instance lock is owned. A stale lock is removed at most once and only after its
PID is proven dead.

Service registration is installer-owned and transactional. The registration
manifest binds the executable SHA-256, service arguments, working directory,
state root, version and activation policy. Install, upgrade, and uninstall are
idempotent and use compensating rollback if either the OS adapter or manifest
write fails.

No OS adapter is selected merely from the current host. Until the ARTIFEX 2.0
supported-platform matrix is approved, the default adapter fails closed and no
live machine service is mutated. This document therefore describes an
implemented platform-neutral foundation, not an OS support claim.
