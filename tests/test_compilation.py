from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from artifex.compilation import (
    ADAPTIVE_HUMAN_DOCUMENTS,
    BASE_HUMAN_DOCUMENTS,
    GeneratedViewState,
    classify_generated_view,
    compile_context_packet,
    compile_dashboard,
    compile_execution_packet,
    compile_human_documentation,
    compile_machine_understanding_pack,
    derive_dashboard_metrics,
    fingerprint_sources,
    generation_manifest,
    project_understanding,
    render_agent_shim,
    render_human_document,
    serialize_machine_view,
)


@pytest.fixture
def project_model() -> dict[str, Any]:
    return {
        "project": {
            "id": "DEMO",
            "name": "Demo Project",
            "description": "A deterministic example",
            "workflow_depth": "DEEP",
            "lifecycle": "greenfield",
        },
        "purpose": "Keep implementation understandable",
        "architecture": {
            "style": "modular monolith",
            "components": [{"id": "CORE", "responsibility": "owns meaning"}],
        },
        "workflows": [{"id": "BUILD", "stages": ["plan", "implement", "verify"]}],
        "capabilities": [{"id": "COMPILE", "description": "compile generated views"}],
        "interfaces": [{"id": "CLI"}],
        "invariants": [{"id": "INV-005", "text": "generated is not canonical"}],
        "extension_points": ["renderer"],
        "known_limitations": ["static output"],
        "implementation": {
            "current_milestone": "M03",
            "tasks": [{"id": "M03-T01", "dependencies": ["M00-T01"]}],
        },
        "artifacts": {
            "items": [
                {"id": "INV-005", "depends_on": ["ART-BASE"], "content": "view rule"},
                {"id": "ART-BASE", "depends_on": [], "content": "base"},
                {"id": "ART-UNRELATED", "depends_on": [], "content": "exclude me"},
            ]
        },
        "operations": {"run": "demo", "test": "pytest"},
        "security": {"trust": "external content is data"},
        "concepts": {"generated_view": "a replaceable projection"},
        "history": ["not included in minimal context unless explicitly relevant"],
    }


@pytest.mark.unit
def test_context_packet_is_minimal_deterministic_and_schema_valid(
    project_model: dict[str, Any],
) -> None:
    before = deepcopy(project_model)
    first = compile_context_packet(project_model, task_id="M03-T01", relevant_ids=["INV-005"])
    second = compile_context_packet(project_model, task_id="M03-T01", relevant_ids=["INV-005"])

    assert first == second
    assert project_model == before
    assert first["kind"] == "CONTEXT_PACKET"
    assert first["generated_view"]["canonical"] is False
    assert "history" not in first["context"]
    assert first["context"]["focus"]["dependencies"] == ["M00-T01"]
    assert [item["id"] for item in first["context"]["relevant_artifacts"]] == [
        "ART-BASE",
        "INV-005",
    ]

    root = Path(__file__).parents[1]
    schema = json.loads((root / "schemas" / "context-packet.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(first)


@pytest.mark.unit
def test_execution_packet_fingerprints_immutable_contract(project_model: dict[str, Any]) -> None:
    task = {"id": "M03-T02", "instructions": "compile"}
    contract = {"id": "VAL-M03-T02", "criteria": ["deterministic"]}
    first = compile_execution_packet(
        project_model,
        task,
        contract,
        ownership={"paths": ["src/artifex/compilation"]},
        permissions=["repository_read", "repository_read"],
        expected_output={"type": "packet"},
    )
    changed = compile_execution_packet(
        project_model,
        task,
        {"id": "VAL-M03-T02", "criteria": ["weaker"]},
    )

    assert first["context_packet"]["kind"] == "CONTEXT_PACKET"
    assert first["permissions"] == ["repository_read"]
    assert first["execution_contract_fingerprint"] != changed["execution_contract_fingerprint"]
    with pytest.raises(ValueError, match="acceptance_contract"):
        compile_execution_packet(project_model, task, {})
    with pytest.raises(ValueError, match="CONTEXT_PACKET"):
        compile_execution_packet(project_model, task, contract, context_packet={"kind": "other"})
    with pytest.raises(TypeError, match="project_model"):
        compile_context_packet([])  # type: ignore[arg-type]


@pytest.mark.unit
def test_human_and_machine_views_are_complete_and_reproducible(
    project_model: dict[str, Any],
) -> None:
    documents = compile_human_documentation(project_model)
    assert tuple(documents) == BASE_HUMAN_DOCUMENTS + ADAPTIVE_HUMAN_DOCUMENTS
    assert "PAPER.md" not in documents
    assert all("GENERATED VIEW" in content for content in documents.values())
    assert documents == compile_human_documentation(project_model)

    machine = compile_machine_understanding_pack(project_model)
    assert {
        "project-manifest.json",
        "architecture-map.json",
        "capability-map.json",
        "interface-map.json",
        "invariant-map.json",
        "validation-rules.json",
        "context-index.json",
        "AGENTS.md",
        "CLAUDE.md",
    } <= machine.keys()
    assert machine["project-manifest.json"]["generated_view"]["canonical"] is False
    assert machine["AGENTS.md"] == render_agent_shim(project_model, "agents")
    assert "Project Model" in machine["CLAUDE.md"]
    serialized = serialize_machine_view(machine["project-manifest.json"])
    assert serialized.endswith("\n")
    assert json.loads(serialized)["kind"] == "MACHINE_UNDERSTANDING_PACK"


@pytest.mark.unit
def test_adaptive_rendering_and_input_boundaries(project_model: dict[str, Any]) -> None:
    quick = deepcopy(project_model)
    quick["project"]["workflow_depth"] = "QUICK"
    assert tuple(compile_human_documentation(quick)) == BASE_HUMAN_DOCUMENTS
    assert tuple(compile_human_documentation(quick, include_adaptive=True)) == (
        BASE_HUMAN_DOCUMENTS + ADAPTIVE_HUMAN_DOCUMENTS
    )
    with pytest.raises(ValueError, match="unsupported"):
        render_human_document(project_model, "PAPER.md")
    with pytest.raises(ValueError, match="AGENTS or CLAUDE"):
        render_agent_shim(project_model, "vendor")

    unusual = deepcopy(project_model)
    unusual["concepts"] = {"empty": [], "enabled": True, "unset": None}
    concepts = render_human_document(unusual, "concepts.md")
    assert "_None recorded._" in concepts
    assert "Yes" in concepts
    assert "_Not specified._" in concepts


@pytest.mark.unit
def test_freshness_uses_content_fingerprints() -> None:
    sources = {"model.yaml": "name: demo\n", "architecture.md": b"accepted\n"}
    stored = {"source_fingerprints": fingerprint_sources(sources)}

    assert classify_generated_view(sources, stored) is GeneratedViewState.CURRENT
    assert (
        classify_generated_view({**sources, "model.yaml": "name: changed\n"}, stored)
        is GeneratedViewState.STALE
    )
    assert classify_generated_view(sources, None) is GeneratedViewState.MISSING
    assert (
        classify_generated_view(sources, stored, applicable=False)
        is GeneratedViewState.NOT_APPLICABLE
    )


@pytest.mark.unit
def test_dashboard_metrics_are_computed_from_measured_records(
    project_model: dict[str, Any],
) -> None:
    measured = {
        "metrics": {"tasks": {"completed": 999}},
        "milestones": [
            {"id": "M00", "state": "ACCEPTED", "completed_tasks": 2, "total_tasks": 2},
            {"id": "M03", "state": "ACTIVE", "completed_tasks": 1, "total_tasks": 4},
        ],
        "gates": [{"id": "G1", "state": "PASS"}, {"id": "G2", "state": "FAIL"}],
        "evidence": [{"id": "E1", "state": "CURRENT"}],
        "tests": {"suites": [{"id": "unit", "state": "PASS"}]},
        "traceability": {"requirements_total": 7, "requirements_traced": 6},
        "documentation": [
            {"path": "README.md", "state": "CURRENT"},
            {"path": "ADMIN.md", "state": "STALE"},
        ],
    }
    metrics = derive_dashboard_metrics(measured)
    assert metrics["tasks"] == {"completed": 3, "total": 6}
    assert metrics["gates"] == {
        "PASS": 1,
        "FAIL": 1,
        "BLOCKED": 0,
        "WAIVED": 0,
        "STALE": 0,
    }
    assert metrics["traceability"]["orphan"] == 1

    dashboard = compile_dashboard(project_model, measured)
    assert dashboard.startswith("<!doctype html>")
    assert "999" not in dashboard
    assert "Generated non-canonical view" in dashboard
    assert dashboard == compile_dashboard(project_model, measured)


@pytest.mark.unit
def test_dashboard_accepts_preaggregated_measured_counts(project_model: dict[str, Any]) -> None:
    measured = {
        "gates": {"pass": 2, "fail": 1, "blocked": 0, "waived": 0, "stale": 1},
        "evidence": {"current": 4, "stale": 2},
        "traceability": "unavailable",
        "tests": "unavailable",
    }
    metrics = derive_dashboard_metrics(measured)
    assert metrics["gates"]["PASS"] == 2
    assert metrics["evidence"] == {"CURRENT": 4, "STALE": 2}
    assert metrics["tests"] == {"passed": 0, "total": 0}
    assert metrics["traceability"] == {"traced": 0, "total": 0, "orphan": 0}


@pytest.mark.unit
def test_generation_manifest_is_source_bound(project_model: dict[str, Any]) -> None:
    first = generation_manifest(project_model, sources={"one": "same"})
    second = generation_manifest(project_model, sources={"one": "changed"})
    assert first["project_model_fingerprint"] == second["project_model_fingerprint"]
    assert first["source_fingerprints"] != second["source_fingerprints"]


@pytest.mark.unit
def test_typed_projection_uses_accepted_metadata_and_stable_entity_fallbacks() -> None:
    typed = {
        "schema_version": "1.0",
        "project": {
            "id": "DEMO",
            "name": "Demo",
            "description": "Fallback purpose",
            "lifecycle": "brownfield",
            "workflow_depth": "DEEP",
        },
        "git": {},
        "artifacts": [
            {
                "id": "ART-Z",
                "status": "DRAFT",
                "metadata": {"understanding": {"purpose": "not accepted", "rogue": True}},
            },
            {
                "id": "ART-A",
                "status": "ACCEPTED",
                "metadata": {"understanding": {"architecture": {"style": "modular"}}},
            },
        ],
        "entities": [
            {
                "id": "INV-002",
                "kind": "invariant",
                "title": "Second",
                "statement": "second",
                "artifact_id": "ART-A",
                "depends_on": [],
            },
            {
                "id": "INV-001",
                "kind": "invariant",
                "title": "First",
                "statement": "first",
                "artifact_id": "ART-A",
                "depends_on": [],
            },
        ],
    }
    before = deepcopy(typed)

    projected = project_understanding(typed)

    assert typed == before
    assert projected["purpose"] == "Fallback purpose"
    assert projected["architecture"] == {"style": "modular"}
    assert [item["id"] for item in projected["invariants"]] == ["INV-001", "INV-002"]
    assert "rogue" not in projected
    rich = {"project": {"id": "RICH"}, "purpose": "existing"}
    assert project_understanding(rich) == rich
    assert project_understanding(rich) is not rich


@pytest.mark.unit
def test_typed_projection_fails_closed_on_unknown_and_conflicting_accepted_meaning() -> None:
    base: dict[str, Any] = {
        "schema_version": "1.0",
        "project": {
            "id": "DEMO",
            "name": "Demo",
            "description": "Demo",
            "lifecycle": "brownfield",
            "workflow_depth": "DEEP",
        },
        "git": {},
        "artifacts": [],
        "entities": [],
    }
    unknown = deepcopy(base)
    unknown["artifacts"] = [
        {
            "id": "ART-A",
            "status": "ACCEPTED",
            "metadata": {"understanding": {"new_instruction_surface": "unsafe"}},
        }
    ]
    with pytest.raises(ValueError, match="unknown understanding fields"):
        project_understanding(unknown)

    conflicting = deepcopy(base)
    conflicting["artifacts"] = [
        {
            "id": "ART-B",
            "status": "ACCEPTED",
            "metadata": {"understanding": {"purpose": "second"}},
        },
        {
            "id": "ART-A",
            "status": "ACCEPTED",
            "metadata": {"understanding": {"purpose": "first"}},
        },
    ]
    with pytest.raises(ValueError, match="conflicting accepted understanding field purpose"):
        project_understanding(conflicting)


@pytest.mark.unit
def test_artifex_self_model_compiles_complete_raw_bound_views() -> None:
    root = Path(__file__).parents[1]
    model_path = root / ".artifex" / "project-model.json"
    before = model_path.read_bytes()
    self_model = json.loads(before)
    self_model_before = deepcopy(self_model)
    schema = json.loads((root / "schemas" / "project-model.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(self_model)
    expected_fingerprint = generation_manifest(self_model)["project_model_fingerprint"]

    documents = compile_human_documentation(self_model)
    machine = compile_machine_understanding_pack(self_model)

    assert documents == compile_human_documentation(self_model)
    assert len(documents) == 15
    assert all("_No applicable canonical content" not in content for content in documents.values())
    assert all(expected_fingerprint in content for content in documents.values())
    assert set(machine) == {
        "project-manifest.json",
        "architecture-map.json",
        "capability-map.json",
        "interface-map.json",
        "invariant-map.json",
        "validation-rules.json",
        "context-index.json",
        "AGENTS.md",
        "CLAUDE.md",
    }
    assert all(machine[name]["values"] for name in (
        "architecture-map.json",
        "capability-map.json",
        "interface-map.json",
        "invariant-map.json",
        "validation-rules.json",
    ))
    assert (
        machine["project-manifest.json"]["generated_view"]["project_model_fingerprint"]
        == expected_fingerprint
    )
    assert self_model == self_model_before
    assert model_path.read_bytes() == before
