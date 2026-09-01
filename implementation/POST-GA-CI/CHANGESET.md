# ARTIFEX Post-GA CI Normalization ChangeSet

## Authority and immutable base

- Canonical ARTIFEX 2.0.0 main/tag: `e6bb13ba165fcb3d9b21cb4598d2f7539cf1bb0a`
- Tag: `v2.0.0`
- Qualified product source: `498cd012830748ea5c492c466146e4129cdbe455`
- Qualified installer SHA-256: `130eb9804369e1ba655fa11ed98be54e606c948b78c30ba297f20d838faca720`
- Maintenance branch: `codex/post-ga-ci-normalization`

The published tag, release assets, qualified R4 artifacts, M12 acceptance, frozen
architecture, and provider qualification evidence are immutable inputs. This
workstream does not rebuild or replace ARTIFEX 2.0.0.

## CS-PGCI-001 — CI and validation infrastructure

- give only history-dependent test jobs a full Git/tag checkout;
- remove the V1-only release validator from current 2.x packaging jobs;
- derive current source/native artifact identity from the exact candidate commit;
- run the historical V1 release harness separately from current 2.x gates;
- reproduce V1-R01 at its frozen intake commit with its exact signature;
- measure the unchanged `>=85%` coverage threshold on current 2.x source without
  injecting incompatible coverage modes into tested subprocesses.

Classification: `WORKFLOW / CI INFRASTRUCTURE`, `HISTORICAL V1 VALIDATOR`,
`RELEASE VERSION DISCOVERY`, `COVERAGE`, and `KNOWN V1 REGRESSION`.

## CS-PGCI-002 — ARTIFEX 2.0.1 candidate maintenance

- retain the existing Windows runtime guard while making `ctypes.windll` portable
  to MyPy on Linux and macOS;
- normalize private Windows ACLs by removing common inherited/explicit broad
  principals before enforcing and verifying the exact user plus LocalSystem DACL;
- recognize the standard `LA` SDDL serialization only when it represents the
  exact current built-in local Administrator SID with reserved RID `500`;
- explicitly enable and verify the inherited DACL on the separate Windows
  provider-workspace root while keeping RunStore and transport state private;
- reject Windows rooted-without-drive artifact paths before joining them to an
  installation root, preserving the lifecycle boundary on every host OS.

This ChangeSet touches distributed source and is therefore separately identified
as ARTIFEX 2.0.1 candidate maintenance. It does not change the v2.0.0 tag or
assets and cannot be published as 2.0.1 without its required release gates.

The post-GA tests also exercise public fail-closed operations, CLI transports,
runtime authority, Project Model integrity, collaborative governance, provider
parsers, lifecycle paths, and service-registration boundaries. They add real
contract coverage; the configured threshold remains unchanged.

## Explicit exclusions

No M6B, M8B, M8C, M10, or M11 work is authorized or included. ATLAS, VM101,
VM105, and all release/qualification assets remain untouched.
