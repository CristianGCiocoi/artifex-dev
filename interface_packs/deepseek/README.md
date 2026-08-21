# ARTIFEX DeepSeek optional interface pack

This pack documents the only DeepSeek product boundary ARTIFEX V1 accepts:
a stable, headless command with structured JSON input and output.

The pack is optional. It must be enabled only when read-only detection reports
`STABLE` and both `headless` and `structured_output` capabilities. Preview,
unknown, and incompatible surfaces fail closed. ARTIFEX Core remains usable
when DeepSeek is absent or the pack is disabled.

Every discovery probe must exit successfully before its output is parsed.
Every result must state its own base commit, execution-contract fingerprint,
and Project Model fingerprint; missing or stale identity never inherits packet
identity.

DeepSeek receives a portable Execution Packet. Its output is an executor claim;
it cannot accept a milestone, replace validator evidence, or transition the
canonical Project Model.
