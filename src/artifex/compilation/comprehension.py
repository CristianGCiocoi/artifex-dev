"""Fresh-context comprehension and optional paper eligibility gates."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from artifex.compilation._util import lookup, model_fingerprint, project_identity
from artifex.compilation.freshness import generation_manifest
from artifex.compilation.projection import project_understanding

COMPREHENSION_TOPICS: tuple[str, ...] = (
    "purpose",
    "architecture",
    "core_components",
    "important_workflows",
    "invariants",
    "run_admin_test",
    "extension_points",
    "known_limitations",
    "implementation_state",
)

_PROMPTS: dict[str, str] = {
    "purpose": "What is this project for?",
    "architecture": "Describe the accepted architecture and its authority boundaries.",
    "core_components": "Identify the Core components and their responsibilities.",
    "important_workflows": "Describe the important workflows and gates.",
    "invariants": "Identify the invariants that constrain implementation.",
    "run_admin_test": "Explain how to run, administer, and test the project.",
    "extension_points": "Identify supported extension points and integration seams.",
    "known_limitations": "State the important current limitations.",
    "implementation_state": "Describe the current measured implementation state.",
}

_TOPIC_PATHS: dict[str, tuple[str, ...]] = {
    "purpose": ("purpose", "project.description"),
    "architecture": ("architecture",),
    "core_components": ("core_components", "architecture.components", "components"),
    "important_workflows": ("workflows", "workflow"),
    "invariants": ("invariants",),
    "run_admin_test": ("operations", "runbook", "testing"),
    "extension_points": ("extension_points", "extensions", "interfaces"),
    "known_limitations": ("known_limitations", "limitations"),
    "implementation_state": ("implementation", "status"),
}


def _concepts(value: Any, *, limit: int = 8) -> list[str]:
    results: list[str] = []

    def visit(item: Any) -> None:
        if len(results) >= limit:
            return
        if isinstance(item, Mapping):
            identifier = item.get("id") or item.get("name") or item.get("title")
            if identifier is not None:
                results.append(str(identifier))
            for key in sorted(item, key=str):
                visit(item[key])
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for child in item:
                visit(child)
        elif isinstance(item, str):
            words = item.strip().split()
            if item.strip() and (len(words) <= 6 or not results):
                results.append(item.strip())

    visit(value)
    return list(dict.fromkeys(results))[:limit]


def build_comprehension_gate(
    project_model: Mapping[str, Any],
    *,
    rubric: Mapping[str, Sequence[str]] | None = None,
    pass_threshold: float = 1.0,
) -> dict[str, Any]:
    """Build a reproducible rubric intended for a repository-only evaluator."""

    if not 0 < pass_threshold <= 1:
        raise ValueError("pass_threshold must be greater than 0 and at most 1")
    read_model = project_understanding(project_model)
    checks: list[dict[str, Any]] = []
    for topic in COMPREHENSION_TOPICS:
        source = lookup(read_model, *_TOPIC_PATHS[topic])
        if rubric is not None and topic in rubric:
            concepts = [str(item) for item in rubric[topic]]
            source_available = True
        else:
            concepts = _concepts(source)
            source_available = source is not None
        checks.append(
            {
                "topic": topic,
                "prompt": _PROMPTS[topic],
                "required_concepts": concepts,
                "source_available": source_available,
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "COMPREHENSION_GATE",
        "fresh_context_required": True,
        "conversation_history_permitted": False,
        "project_model_fingerprint": model_fingerprint(project_model),
        "pass_threshold": pass_threshold,
        "checks": checks,
    }


def _normalized(text: str) -> str:
    return " ".join(re.findall(r"[\w-]+", text.casefold(), flags=re.UNICODE))


def evaluate_comprehension(
    gate: Mapping[str, Any], responses: Mapping[str, str], *, fresh_context: bool = True
) -> dict[str, Any]:
    """Evaluate explicit responses against the immutable gate rubric."""

    checks = gate.get("checks")
    if not isinstance(checks, Sequence) or isinstance(checks, (str, bytes, bytearray)):
        raise ValueError("gate checks are missing")
    results: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, Mapping) or "topic" not in check:
            raise ValueError("gate contains an invalid check")
        topic = str(check["topic"])
        response = str(responses.get(topic, ""))
        normalized = _normalized(response)
        concepts = [str(item) for item in check.get("required_concepts", ())]
        missing = [concept for concept in concepts if _normalized(concept) not in normalized]
        # A rubric with no extracted concepts still requires a substantive answer.
        source_available = bool(check.get("source_available", True))
        passed = (
            source_available
            and bool(normalized)
            and not missing
            and len(normalized.split()) >= 3
        )
        results.append(
            {
                "topic": topic,
                "state": "PASS" if passed else "FAIL",
                "missing_concepts": missing,
            }
        )
    passed_count = sum(item["state"] == "PASS" for item in results)
    score = passed_count / len(results) if results else 0.0
    threshold = float(gate.get("pass_threshold", 1.0))
    context_valid = fresh_context or not bool(gate.get("fresh_context_required", True))
    return {
        "state": "PASS" if context_valid and score >= threshold else "FAIL",
        "score": score,
        "fresh_context": fresh_context,
        "checks": results,
    }


class PaperCompiler(Protocol):
    """Optional renderer seam; V1 does not require an implementation."""

    def compile(self, project_model: Mapping[str, Any]) -> str: ...


def evaluate_paper_eligibility(
    project_model: Mapping[str, Any], *, criteria: Mapping[str, bool] | None = None
) -> dict[str, Any]:
    """Evaluate explicit, inspectable criteria without making paper mandatory."""

    read_model = project_understanding(project_model)
    identity = project_identity(read_model)
    if criteria is None:
        paper = lookup(read_model, "paper")
        paper = paper if isinstance(paper, Mapping) else {}
        criteria = {
            "deep_workflow": str(identity.get("workflow_depth", "")).upper() == "DEEP",
            "novel_contribution": bool(paper.get("novel_contribution", False)),
            "reproducible_evidence": bool(paper.get("reproducible_evidence", False)),
            "architect_approved": bool(paper.get("architect_approved", False)),
        }
    normalized = {str(name): bool(value) for name, value in sorted(criteria.items())}
    failed = [name for name, passed in normalized.items() if not passed]
    return {
        "eligible": bool(normalized) and not failed,
        "state": "ELIGIBLE" if normalized and not failed else "NOT_APPLICABLE",
        "criteria": normalized,
        "failed_criteria": failed,
    }


def compile_optional_paper(
    project_model: Mapping[str, Any], compiler: PaperCompiler | None = None
) -> dict[str, Any]:
    """Invoke an optional compiler only after eligibility; otherwise emit a status view."""

    eligibility = evaluate_paper_eligibility(project_model)
    output: dict[str, Any] = {
        "generated_view": generation_manifest(project_model, generator="paper-placeholder-v1"),
        "eligibility": eligibility,
        "state": eligibility["state"],
        "content": None,
    }
    if not eligibility["eligible"]:
        return output
    if compiler is None:
        output["state"] = "ELIGIBLE_UNCOMPILED"
        return output
    content = compiler.compile(project_model)
    if not isinstance(content, str):
        raise TypeError("paper compiler must return str")
    output.update({"state": "CURRENT", "content": content})
    return output


# Explicit gate-oriented aliases.
compile_comprehension_gate = build_comprehension_gate
paper_eligibility_gate = evaluate_paper_eligibility


__all__ = [
    "COMPREHENSION_TOPICS",
    "PaperCompiler",
    "build_comprehension_gate",
    "compile_comprehension_gate",
    "compile_optional_paper",
    "evaluate_comprehension",
    "evaluate_paper_eligibility",
    "paper_eligibility_gate",
]
