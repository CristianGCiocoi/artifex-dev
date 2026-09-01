# ARTIFEX 2.0.0 GA

ARTIFEX 2.0.0 is the accepted Core GA release for durable, project-centric,
provider-neutral engineering orchestration. The exact Windows x86_64 installer
is bound to qualified source commit `498cd012830748ea5c492c466146e4129cdbe455`
and SHA-256
`130eb9804369e1ba655fa11ed98be54e606c948b78c30ba297f20d838faca720`.

## Qualification

- 18/18 mandatory Journeys passed.
- 12/12 Core claims passed.
- 10/10 evidence classes passed.
- Codex and Claude passed standalone first-class operation and combined J11/J20.
- J20 used the installed native public composition, real providers, the managed
  service, 50 public process calls, restart/recovery and separated execution,
  validation, acceptance and Project promotion authority.
- J09 preserved a real V1 Git/semantic baseline, proved rollback and completed
  the first new 2.0 Run without fabricating legacy runtime history.

The qualified Windows artifact is unsigned; no Authenticode signing claim is
made. Integrity is enforced by the published installer and provenance hashes.
Linux and macOS remain supported targets but are not GA-certified release cells
for this manifest.

## Provider scope

Codex and Claude are certified for `INTERACTION` and `EXECUTION_IMPLEMENTER`.
Manual operation is the no-provider fallback. Hermes, Pandora, DeepSeek and
ATLAS runtime capabilities are not claimed by this release.

## Preserved historical regression

`V1-R01-DASHBOARD-FIXTURE-SCHEMA-DRIFT` remains reproduced, unwaived and
unrepaired. It is historical V1 fixture evidence and does not weaken any M12
release gate.

The authoritative release record is
[`/.artifex/releases/v2.0.0.yaml`](../../.artifex/releases/v2.0.0.yaml), with the
claim matrix, Journey evidence and provider/migration records under
`implementation/`.
