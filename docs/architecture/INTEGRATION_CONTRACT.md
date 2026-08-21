# ARTIFEX — Integration Contract v1

## Integration roles

An integration can advertise any subset:
- `interface`
- `harness`
- `implementer`
- `research_provider`

## Required metadata

- ID/name/version
- compatibility range with ARTIFEX Core
- tested external product versions
- capabilities
- health status
- configuration provenance

## Core capability examples

- interactive
- headless
- resume
- skills
- MCP
- worktrees
- subagents
- structured_output
- repository_read
- repository_write
- test_execution
- background_jobs

## Behavioral contract

Core workflow logic must query capabilities and policy, not branch on vendor names except inside the adapter implementation.

## Execution packet

An implementer receives:
- task contract;
- relevant context only;
- base commit;
- Project Model fingerprint;
- relevant interfaces/invariants;
- file/surface ownership;
- acceptance criteria;
- expected result contract.

No parent transcript is required.

## Required V1 integrations

### Manual
No external agent. Produces portable Execution Packets and accepts manually supplied results.

### Hermes
Preferred interface/harness/implementer/research provider when available.

### Codex
First-class standalone interface+harness+implementer.

### Claude
First-class standalone interface+harness+implementer.

### DeepSeek Harness
Optional harness/implementer pack. Prefer stable/headless product boundary over internal Cordis APIs.

### Pandora
Optional research_provider only.

## Conformance suite

Every relevant integration must test:
- project status/context read;
- stage execution;
- artifact/result submission;
- validation interaction;
- cancellation/failure mapping;
- compatibility reporting.

Codex/Claude/Hermes additionally participate in `INT-CONTINUITY`.
