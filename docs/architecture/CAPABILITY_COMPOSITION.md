# Capability Composition and Codex Authority

ARTIFEX 2.0 composes providers at runtime from persisted, secret-free setup. The
Capability Graph is runtime authority for global provider state; it does not own
Project semantics, acceptance, credentials, or provider certification claims.

## Readiness and eligibility

Provider instance readiness advances explicitly through:

`DETECTED → CONFIGURED → AUTHENTICATED → HEALTHY → REGISTERED → AVAILABLE`

The states are not interchangeable. In particular, successful discovery or a
version probe cannot authorize dispatch. The contextual Resolver separately
evaluates `AVAILABLE_FOR(Project, ProjectJob, ExecutionEnvelope, Actor,
DataClassification)`. It checks the requested role, release certification,
Project and Envelope scope, actor delegation, data policy, governance mode, and
credential-reference scope. Every denial is fail-closed and auditable.

## Persisted setup and credentials

Project setup records provider identifiers, requested roles, governance mode,
an executable command reference, and opaque credential references. It never
records a credential value. A fresh ARTIFEX process must load and validate the
persisted setup before it can register a provider. Credential values are resolved
only at the dispatch boundary by a scoped broker and are excluded from Project
Git, RunStore payloads, prompts, results, evidence, documentation, and dashboard
projections.

For Codex, a native authenticated CLI session is represented by a scoped opaque
reference. Authentication is established by a bounded non-mutating readiness
probe; the existence of local configuration files is not authentication proof.

## Public composition

CLI, MCP, and other clients use the same default `Application` composition and
public operations:

- `providers.graph`
- `providers.readiness`
- `providers.resolve`
- `providers.interact`
- `providers.certifications`
- `runtime.provider.execute`

No custom Application factory or direct adapter injection is valid M3 delivery
evidence. Provider INTERACTION and EXECUTION_IMPLEMENTER roles are certified
independently.

## Automated execution boundary

A Codex execution dispatch requires an authenticated delegated actor, an
approved immutable L2-or-higher Execution Envelope, a role-certified and
contextually eligible provider, a baseline-bound isolated Git workspace, and a
scoped credential reference. The dispatcher runs Codex with a bounded command,
explicit workspace sandbox, structured output, and timeout/recovery handling.

Codex completion creates only a Result Claim and evidence. The
ExecutionCoordinator may transition runtime state but cannot accept the result.
Validation records durable evidence, Acceptance Authority decides the result,
and Project Authority alone promotes a verified workspace delta after a fresh
baseline-conflict check. Ambiguous external outcomes become `UNKNOWN` and require
reconciliation before retry.

## M3 outcome boundary

M3 proves the installed-wheel public Codex vertical slice and provider setup
persistence (J16). It exercises the applicable installed-wheel portion of J01
without claiming M7's later fresh-machine installation/bootstrap proof. M7 and
M12 revalidate the full release journey.
