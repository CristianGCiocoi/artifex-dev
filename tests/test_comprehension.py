from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from artifex.compilation import (
    COMPREHENSION_TOPICS,
    build_comprehension_gate,
    compile_optional_paper,
    evaluate_comprehension,
    evaluate_paper_eligibility,
)


def _model(*, eligible: bool = False) -> dict[str, Any]:
    return {
        "project": {
            "id": "DEMO",
            "name": "Demo",
            "description": "A documented system",
            "workflow_depth": "DEEP",
        },
        "paper": {
            "novel_contribution": eligible,
            "reproducible_evidence": eligible,
            "architect_approved": eligible,
        },
    }


@pytest.mark.unit
def test_comprehension_gate_covers_repository_only_understanding() -> None:
    rubric = {topic: [f"concept-{topic}"] for topic in COMPREHENSION_TOPICS}
    gate = build_comprehension_gate(_model(), rubric=rubric)
    assert gate["fresh_context_required"] is True
    assert gate["conversation_history_permitted"] is False
    assert [check["topic"] for check in gate["checks"]] == list(COMPREHENSION_TOPICS)

    responses = {
        topic: f"This answer explains concept-{topic} clearly"
        for topic in COMPREHENSION_TOPICS
    }
    result = evaluate_comprehension(gate, responses)
    assert result["state"] == "PASS"
    assert result["score"] == 1.0

    responses["purpose"] = "wrong short answer"
    failed = evaluate_comprehension(gate, responses)
    assert failed["state"] == "FAIL"
    assert failed["checks"][0]["missing_concepts"] == ["concept-purpose"]
    assert evaluate_comprehension(gate, responses, fresh_context=False)["state"] == "FAIL"


@pytest.mark.unit
def test_comprehension_gate_rejects_invalid_threshold() -> None:
    with pytest.raises(ValueError, match="pass_threshold"):
        build_comprehension_gate(_model(), pass_threshold=0)


@pytest.mark.unit
def test_derived_gate_fails_topics_without_canonical_sources() -> None:
    gate = build_comprehension_gate(_model())
    responses = {topic: "a sufficiently long generic answer" for topic in COMPREHENSION_TOPICS}
    result = evaluate_comprehension(gate, responses)
    assert result["state"] == "FAIL"
    assert any(check["state"] == "FAIL" for check in result["checks"])

    with pytest.raises(ValueError, match="checks"):
        evaluate_comprehension({}, responses)
    with pytest.raises(ValueError, match="invalid check"):
        evaluate_comprehension({"checks": [None]}, responses)


class _Paper:
    def compile(self, project_model: Mapping[str, Any]) -> str:
        return f"# {project_model['project']['name']} paper\n"


class _InvalidPaper:
    def compile(self, project_model: Mapping[str, Any]) -> str:
        del project_model
        return 7  # type: ignore[return-value]


@pytest.mark.unit
def test_paper_is_optional_and_compiled_only_when_eligible() -> None:
    ineligible = compile_optional_paper(_model())
    assert ineligible["state"] == "NOT_APPLICABLE"
    assert ineligible["content"] is None

    eligibility = evaluate_paper_eligibility(_model(eligible=True))
    assert eligibility["eligible"] is True
    assert compile_optional_paper(_model(eligible=True))["state"] == "ELIGIBLE_UNCOMPILED"

    compiled = compile_optional_paper(_model(eligible=True), _Paper())
    assert compiled["state"] == "CURRENT"
    assert compiled["content"] == "# Demo paper\n"
    with pytest.raises(TypeError, match="must return str"):
        compile_optional_paper(_model(eligible=True), _InvalidPaper())


@pytest.mark.unit
def test_paper_eligibility_accepts_an_explicit_policy() -> None:
    result = evaluate_paper_eligibility(
        _model(), criteria={"reproducible": True, "architect_gate": False}
    )
    assert result["eligible"] is False
    assert result["failed_criteria"] == ["architect_gate"]


@pytest.mark.unit
def test_artifex_self_model_has_all_nine_comprehension_sources() -> None:
    root = Path(__file__).parents[1]
    self_model = json.loads((root / ".artifex" / "project-model.json").read_text())

    first = build_comprehension_gate(self_model)
    second = build_comprehension_gate(self_model)

    assert first == second
    assert len(first["checks"]) == len(COMPREHENSION_TOPICS) == 9
    assert all(check["source_available"] for check in first["checks"])
    assert all(check["required_concepts"] for check in first["checks"])
    assert first["project_model_fingerprint"] == compile_optional_paper(self_model)[
        "generated_view"
    ]["project_model_fingerprint"]
