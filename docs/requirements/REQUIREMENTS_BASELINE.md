# ARTIFEX — Requirements Baseline v1.0

## D1 — Project Intake

- **REQ-F-001** Initialize a greenfield ARTIFEX project.
- **REQ-F-002** Adopt an existing repository without destroying existing content.
- **REQ-F-003** Classify workflow depth as QUICK, STANDARD or DEEP.
- **REQ-F-004** Detect/record Git state and establish a versioned baseline for managed development.

## D2 — Development Research

- **REQ-F-010** Perform targeted software-development research needed for a decision.
- **REQ-F-011** Support pluggable `research_provider` integrations.
- **REQ-F-012** Normalize research output through `ResearchBundle`.
- **REQ-F-013** Treat external content as untrusted data, never instruction authority.
- **REQ-F-014** Support optional Pandora research without Core dependency.

## D3 — Design

- **REQ-F-020** Maintain requirements, constraints, assumptions and non-goals.
- **REQ-F-021** Produce/maintain architecture, interfaces, workflows and invariants.
- **REQ-F-022** Maintain ADRs with alternatives, rationale and revisit triggers.
- **REQ-F-023** Bind resource constraints into design validation when supplied.

## D4 — Planning

- **REQ-F-030** Convert architecture into milestones/tasks with dependencies.
- **REQ-F-031** Each executable task must have an Acceptance Contract.
- **REQ-F-032** Support explicit file/surface ownership and integration tasks.
- **REQ-F-033** Support ChangeSets for meaningful brownfield changes.
- **REQ-F-034** Maintain requirements→design→task→evidence traceability.

## D5 — Execution

- **REQ-F-040** Support integration roles: interface, harness, implementer, research_provider.
- **REQ-F-041** Support Manual integration without any external harness.
- **REQ-F-042** Hermes must be the preferred orchestrator when available.
- **REQ-F-043** Codex must work standalone as interface+harness+implementer.
- **REQ-F-044** Claude must work standalone as interface+harness+implementer.
- **REQ-F-045** Support optional DeepSeek Harness integration.
- **REQ-F-046** Execution packets must bind base commit, task contract and project fingerprint.
- **REQ-F-047** Return `REBASE_REQUIRED` when execution result is stale.

## D6 — Validation

- **REQ-F-050** Canonical acceptance state is controlled by ARTIFEX Core, not executor claims.
- **REQ-F-051** Prefer deterministic validators over LLM judgment when possible.
- **REQ-F-052** Maintain Evidence Ledger entries bound to verified state.
- **REQ-F-053** Support task, integration, milestone and release gates.
- **REQ-F-054** Evidence becomes STALE when its verified basis changes materially.
- **REQ-F-055** Acceptance criteria cannot be silently weakened after execution begins.
- **REQ-F-056** Waivers require explicit authority and provenance.
- **REQ-F-057** Detect premature completion, self-certification and evidence tampering.
- **REQ-F-058** Detect workflow no-progress loops via liveness policy.

## D7 — Understanding

- **REQ-F-060** Compile human documentation from canonical Project Model.
- **REQ-F-061** Compile machine-first context/views from canonical Project Model.
- **REQ-F-062** Generate an implementation dashboard from measured state/evidence.
- **REQ-F-063** Detect CURRENT/STALE/MISSING/N/A documentation state.
- **REQ-F-064** Support a fresh-context Comprehension Gate.
- **REQ-F-065** Produce at least README, User Guide, Admin Guide and Developer Guide for STANDARD/DEEP projects.
- **REQ-F-066** Support optional paper generation only when eligibility criteria are met.

## D8 — Learning

- **REQ-F-070** Capture project lessons with provenance.
- **REQ-F-071** Maintain instance-level knowledge separately from project knowledge.
- **REQ-F-072** Generate Improvement Proposals.
- **REQ-F-073** Support candidate overlays without modifying Core directly.
- **REQ-F-074** Store confidence, sensitivity/scope and revisit triggers for knowledge.

## D9 — Lifecycle

- **REQ-F-080** Support Core/Profile/Instance/Project/Run separation conceptually.
- **REQ-F-081** Local evolution must be rebaseable over future Core releases.
- **REQ-F-082** Upgrade flow must classify local changes as CARRY_FORWARD, SUPERSEDED, REVALIDATE or CONFLICT.
- **REQ-F-083** Updates must activate atomically after validation.
- **REQ-F-084** Project semantic truth must remain reconstructable from repository artifacts.

## D10 — Memory

- **REQ-F-090** Harness-native memory is auxiliary only.
- **REQ-F-091** No correctness-critical state may exist only in harness memory.
- **REQ-F-092** Support memory promotion RUN→PROJECT→INSTANCE with policy.
- **REQ-F-093** Wider-scope promotion must require stronger evidence.

## D11 — Accessibility

- **REQ-F-100** Support BEGINNER, GUIDED and EXPERT experience modes independently of workflow depth.
- **REQ-F-101** BEGINNER mode must not reduce architecture/validation rigor.
- **REQ-F-102** High-impact decisions must explain recommendation, gains, trade-offs and reversibility.
- **REQ-F-103** A beginner install must not require manual Python/pip/venv setup.
- **REQ-F-104** Provide `doctor`/environment diagnostics and safe remediation.

## D12 — Resource Awareness

- **REQ-F-110** Resource Envelope is optional.
- **REQ-F-111** Separate development resources from target runtime resources.
- **REQ-F-112** Distinguish HARD constraints from SOFT preferences.
- **REQ-F-113** Unspecified resources mean unspecified, not unlimited.
- **REQ-F-114** Detect resource contradictions when measurable.

## Non-functional

- **REQ-NF-001** Agent-neutral.
- **REQ-NF-002** Filesystem/Git canonical semantic truth.
- **REQ-NF-003** No mandatory DB in V1.
- **REQ-NF-004** No mandatory daemon in V1.
- **REQ-NF-005** Replaceable integrations.
- **REQ-NF-006** Graceful degradation when an integration is unavailable.
- **REQ-NF-007** Cross-platform Windows/Linux/macOS target.
- **REQ-NF-008** Inspectable state without proprietary UI.
- **REQ-NF-009** Secret-safe artifacts/evidence/memory.
- **REQ-NF-010** Self-improvement cannot autonomously expand privileges.
- **REQ-NF-011** Interface switch must preserve semantic state.
- **REQ-NF-012** Core V1 must be distributable without requiring users to install Python manually.
