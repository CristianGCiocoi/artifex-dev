# DeepSeek Provider Guide

DeepSeek support is optional and experimental. ARTIFEX Core remains usable when DeepSeek is
missing or disabled.

## Configure

Use the public integration setup flow and select `deepseek`. The generated plan must show:

- role `EXECUTION_IMPLEMENTER` only;
- governance mode `PROVIDER_MANAGED`;
- command `deepseek` with no pre-supplied flags;
- broker `deepseek-native-session` with a secret-free reference.

Approve the reversible setup plan before applying it. ARTIFEX writes only
`.artifex/integrations.json`; it does not modify DeepSeek vendor configuration.

## Verify readiness

Check `providers.graph` and `providers.readiness` from a fresh process. `AVAILABLE` requires
a supported stable 1.x executable, headless structured output and a successful native
authentication status containing JSON `{"authenticated": true}`. A zero exit code, plain
text such as `authenticated`, malformed JSON or an explicit false value fails closed.
`DETECTED` or `CONFIGURED` alone is not executable readiness.

Then use `providers.resolve` with the actual ProjectJob, approved Execution Envelope,
delegated actor and data classification. A globally healthy provider can still be rejected
for the current context. In the blocked M8C source baseline, it must be rejected with no
default certified execution role until live certification evidence is independently anchored.

## Interpret certification

Use `providers.certifications` with `provider_id=deepseek`. Expected states are:

- `EXECUTION_IMPLEMENTER`: at most `PUBLIC_COMPOSITION_VERIFIED` until a real accepted and
  promoted live execution exists;
- `INTERACTION`: `EXPERIMENTAL_NOT_CLAIMED`;
- `HARNESS`: `EXPERIMENTAL_NOT_CLAIMED`.

Never use V1 adapter tests, a config write, an authentication status, another provider's
result, or a synthetic runner as proof of live DeepSeek certification.
Legacy or promoted-style receipts without provider-version, executable, semantic-auth-probe
and installed-wheel digest bindings are also ineligible for live certification.

## Live qualification gate

A release owner may run the installed-wheel M8C qualifier only after selecting and
approving the supported executable, endpoint/model policy and native authenticated session.
The qualifier must use an empty local capability-evidence store and must not read, print or
persist credentials. Live success still requires independent validation, Acceptance
Authority and Project Authority promotion before the certification receipt is valid.
