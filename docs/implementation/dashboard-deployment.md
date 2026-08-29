# ARTIFEX dashboard deployment

The ARTIFEX operational dashboard is published at `https://artifex-dev.crugger.lan`.
The ARTIFEX 2.0 implementation-control dashboard is published independently at
`https://artifex-impl.crugger.lan` so the immutable V1 release projection is not
replaced by in-progress 2.0 milestone state.
It is a read-only, non-canonical projection of committed ARTIFEX authority: the
release record, immutable S/G/R chain, validation evidence, artifact hashes and
audit history remain authoritative.

## Topology

- VM100 (`192.168.1.193`) serves the static dashboard through the existing
  `caddy_proxy` network, alongside ATLAS, Pandora and ORPHEUS.
- Caddy uses internal TLS, serves private LAN/VPN source ranges only, and returns
  `404` for plain HTTP.
- Each deployment uploads a timestamped static release under
  `/opt/stacks/artifex-dashboard/releases/` or
  `/opt/stacks/artifex-implementation-dashboard/releases/`; `current` is an
  atomic symlink.
- The deployer snapshots the Caddy, DNS, compose and previous `current` state
  before mutation and automatically restores it if validation fails.

## Publish

Regenerate and validate the derived state before publishing:

```powershell
# Operational V1 release projection
uv run python tools/render_dashboard.py --write
uv run python tools/render_dashboard.py
python tools/deploy_dashboard_lan.py --target operational --apply

# ARTIFEX 2.0 implementation-control projection
uv run python -m tools.artifex2.control_plane --write
uv run python -m tools.artifex2.control_plane
python tools/deploy_dashboard_lan.py --target implementation --apply
```

The deployer verifies dashboard content and state hash on VM100, DNS, HTTPS
(`200`), HTTP fail-closed behavior (`404`), and ATLAS/Pandora/ARTIFEX V1
dashboard regressions. It also refuses a target whose state identity does not
match the selected dashboard.
