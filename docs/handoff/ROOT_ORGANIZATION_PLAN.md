# ARTIFEX — Root Handoff Reorganization Plan

The human places all handoff files in the project root. Codex must reorganize them before implementation.

## Target structure

```
artifex-dev/
├── README.md
├── LICENSE
├── pyproject.toml
├── uv.lock
├── AGENTS.md
├── CLAUDE.md
├── .gitignore
├── .github/workflows/
├── src/artifex/
├── tests/
├── schemas/
├── scripts/
├── docs/
│   ├── handoff/
│   ├── product/
│   ├── architecture/
│   │   ├── adr/
│   │   └── escalations/
│   ├── requirements/
│   ├── implementation/
│   │   ├── milestones/
│   │   ├── acceptance/
│   │   └── dashboard/
│   ├── security/
│   └── guides/
└── .artifex/
    ├── project.yaml
    ├── status.yaml
    ├── model/
    ├── changes/
    ├── decisions/
    ├── implementation/
    ├── validation/
    │   ├── contracts/
    │   ├── evidence/
    │   ├── gates/
    │   └── waivers/
    ├── knowledge/
    ├── generated/
    └── history/
```

## Move mapping

- `00_START_HERE_CODEX_ORCHESTRATOR.md` → `docs/handoff/CODEX_ORCHESTRATOR_BOOTSTRAP.md`
- `01_HANDOFF_MANIFEST.yaml` → `docs/handoff/HANDOFF_MANIFEST.yaml`
- `02_PRODUCT_DEFINITION.md` → `docs/product/PRODUCT_DEFINITION.md`
- `03_REQUIREMENTS_BASELINE.md` → `docs/requirements/REQUIREMENTS_BASELINE.md`
- `04_ARCHITECTURE_V1_ACCEPTED.md` → `docs/architecture/ARCHITECTURE.md`
- `05_INVARIANTS.md` → `docs/architecture/INVARIANTS.md`
- `06_THREAT_FAILURE_ANALYSIS.md` → `docs/security/THREAT_FAILURE_ANALYSIS.md`
- `07_ROADMAP_V1_V3.md` → `docs/product/ROADMAP.md`
- `08_IMPLEMENTATION_PLAN_V1_ACCEPTED.md` → `docs/implementation/IMPLEMENTATION_PLAN.md`
- `10_VALIDATION_EVIDENCE_SPEC.md` → `docs/architecture/VALIDATION_EVIDENCE_SPEC.md`
- `11_INTEGRATION_CONTRACT.md` → `docs/architecture/INTEGRATION_CONTRACT.md`
- `12_MEMORY_EVOLUTION_SPEC.md` → `docs/architecture/MEMORY_EVOLUTION_SPEC.md`
- `13_COMPILATION_UNDERSTANDING_SPEC.md` → `docs/architecture/COMPILATION_UNDERSTANDING_SPEC.md`
- `14_BEGINNER_RESOURCE_SPEC.md` → `docs/product/BEGINNER_RESOURCE_SPEC.md`
- `15_PANDORA_RESEARCH_SPEC.md` → `docs/architecture/PANDORA_RESEARCH_SPEC.md`
- schema drafts `16`–`20` → `schemas/handoff/` initially; promote into canonical schemas during M0/M1.
- templates `21`–`23` → `docs/implementation/templates/`.
- `Mxx_*.md` → `docs/implementation/milestones/`.

Preserve `99_SHA256SUMS.txt` in `docs/handoff/`.

After moving, make the first Git commit:
`chore: import accepted ARTIFEX architecture and complete V1 handoff`
