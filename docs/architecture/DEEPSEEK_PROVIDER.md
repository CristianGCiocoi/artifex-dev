# DeepSeek Provider Boundary

ARTIFEX 2.0 treats DeepSeek as an optional, experimental provider. Its absence has no
effect on Core availability. M8C productizes one claim only:
`DeepSeek EXECUTION_IMPLEMENTER` through the stable DeepSeek 1.x headless,
structured-output CLI boundary.

`INTERACTION` and `HARNESS` are explicitly not claimed. The V1 interface pack may still
describe its historical harness role, but that does not confer an ARTIFEX 2.0 release
claim or public runtime authority.

## Composition and readiness

Project-owned setup stores only a scoped `deepseek-native-session` credential reference.
It never stores a token, API key, endpoint credential, or vendor configuration. A fresh
runtime performs version and `run --help` discovery, then a secret-free native-session
status probe. A zero exit code is insufficient: the status response must be valid JSON
whose `authenticated` field is exactly `true`. The instance progresses through detected, configured, authenticated,
healthy, registered and available states only when every preceding check passes.

The supported experimental range is `>=1.0.0,<2`. Preview versions, other major versions,
missing structured-output/headless flags, authentication failure and missing executables
all remain unavailable. Global availability still does not imply contextual eligibility;
the resolver also evaluates the Project, ProjectJob, Execution Envelope, actor delegation,
capabilities and data classification.

Availability is not dispatch authority. While M8C lacks independently anchored
`LIVE_ROLE_CERTIFIED` evidence, the default Capability Graph exposes no certified DeepSeek
role and contextual resolution rejects execution with `ROLE_NOT_CERTIFIED`, even if the
executable, version, help surface and authentication probe all look valid.

## Execution authority

DeepSeek receives a transcript-independent Execution Packet inside an isolated Execution
Workspace. The command cannot pre-supply caller flags. ARTIFEX independently hashes owned
artifacts and rejects any change outside Envelope-owned paths. A provider result is an
executor claim only. Validation evidence, Acceptance Authority and Project Authority
promotion remain separate, and only an accepted and promoted result can create an
EXECUTION_IMPLEMENTER certification receipt. A live-eligible DeepSeek receipt also binds
the provider version, executable digest, semantic authentication-probe digest and installed
shipping-wheel digest. Missing or partial bindings cannot advance the certification ladder.

The current boundary is not a host security sandbox. Network, tool and credential access
must also be explicitly present in the approved Execution Envelope and local deployment
policy.

## Certification truth

Adapter, conformance, packaging and public-composition evidence do not equal live role
certification. `LIVE_ROLE_CERTIFIED` requires a real supported DeepSeek execution from the
installed wheel, independently validated, accepted and promoted. Until that occurs, the
public certification surface reports `PUBLIC_COMPOSITION_VERIFIED` and the milestone must
not claim DeepSeek execution support.
