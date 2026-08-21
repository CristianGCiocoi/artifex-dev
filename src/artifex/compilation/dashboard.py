"""Measured-state dashboard compilation."""

from __future__ import annotations

import html
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from artifex.compilation._util import project_identity
from artifex.compilation.freshness import generation_manifest


def _records(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [item for item in value.values() if isinstance(item, Mapping)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _state_counts(value: Any, states: Sequence[str]) -> dict[str, int]:
    records = _records(value)
    if records:
        counts = Counter(
            str(record.get("state", record.get("status", "UNKNOWN"))).upper()
            for record in records
        )
        return {state: counts[state] for state in states}
    if isinstance(value, Mapping):
        return {state: int(value.get(state.lower(), value.get(state, 0))) for state in states}
    return dict.fromkeys(states, 0)


def derive_dashboard_metrics(measured_state: Mapping[str, Any]) -> dict[str, Any]:
    """Derive every displayed metric; an input ``metrics`` narration is ignored."""

    milestones = _records(measured_state.get("milestones"))
    tasks_completed = sum(int(item.get("completed_tasks", 0)) for item in milestones)
    tasks_total = sum(int(item.get("total_tasks", 0)) for item in milestones)
    accepted = sum(str(item.get("state", "")).upper() == "ACCEPTED" for item in milestones)
    test_state = measured_state.get("tests")
    tests = (
        _records(test_state.get("suites", ()))
        if isinstance(test_state, Mapping)
        else _records(test_state)
    )
    tests_passed = sum(
        str(item.get("state", item.get("status", ""))).upper() in {"PASS", "PASSED"}
        for item in tests
    )
    traceability = measured_state.get("traceability", {})
    if not isinstance(traceability, Mapping):
        traceability = {}
    requirements_total = int(traceability.get("requirements_total", 0))
    requirements_traced = int(traceability.get("requirements_traced", 0))
    return {
        "milestones": {"accepted": accepted, "total": len(milestones)},
        "tasks": {"completed": tasks_completed, "total": tasks_total},
        "gates": _state_counts(
            measured_state.get("gates"), ("PASS", "FAIL", "BLOCKED", "WAIVED", "STALE")
        ),
        "evidence": _state_counts(measured_state.get("evidence"), ("CURRENT", "STALE")),
        "tests": {"passed": tests_passed, "total": len(tests)},
        "traceability": {
            "traced": requirements_traced,
            "total": requirements_total,
            "orphan": int(
                traceability.get(
                    "orphan_requirements", max(0, requirements_total - requirements_traced)
                )
            ),
        },
        "documentation": _state_counts(
            measured_state.get("documentation"),
            ("CURRENT", "STALE", "MISSING", "NOT_APPLICABLE"),
        ),
    }


def compile_dashboard(
    project_model: Mapping[str, Any], measured_state: Mapping[str, Any]
) -> str:
    """Render a standalone static HTML view over supplied measured state."""

    identity = project_identity(project_model)
    metrics = derive_dashboard_metrics(measured_state)
    payload = {
        "schema_version": "1.0",
        "generated_view": generation_manifest(
            project_model,
            sources={"project_model": project_model, "measured_state": measured_state},
            generator="static-dashboard-v1",
        ),
        "project": identity,
        "metrics": metrics,
    }
    name = html.escape(str(identity.get("name", identity.get("id", "Project"))))
    cards = []
    for group in sorted(metrics):
        values = metrics[group]
        detail = " · ".join(
            f"{html.escape(str(key))}: {html.escape(str(values[key]))}" for key in sorted(values)
        )
        cards.append(
            f'<section class="card"><h2>{html.escape(group.title())}</h2>'
            f"<p>{detail}</p></section>"
        )
    embedded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).replace("</", "<\\/")
    return "\n".join(
        (
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            f"<title>{name} implementation dashboard</title>",
            "<style>body{font:16px system-ui;margin:2rem;max-width:72rem}"
            ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));"
            "gap:1rem}.card{border:1px solid #bbb;border-radius:.5rem;padding:1rem}"
            "small{color:#555}</style>",
            "</head><body>",
            f"<h1>{name} implementation dashboard</h1>",
            "<small>Generated non-canonical view; values are derived from measured state.</small>",
            f'<main class="grid">{"".join(cards)}</main>',
            f'<script id="artifex-dashboard-state" type="application/json">{embedded}</script>',
            "</body></html>",
            "",
        )
    )


render_dashboard = compile_dashboard


__all__ = ["compile_dashboard", "derive_dashboard_metrics", "render_dashboard"]
