# ruff: noqa: E501
"""Validate and deterministically render ARTIFEX 2.0 implementation-control state."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

REQUIRED_CONTROL_PATHS = (
    "PROGRAM-STATE.yaml",
    "MILESTONE-DAG.yaml",
    "WORKSTREAM-REGISTRY.yaml",
    "CONTRACT-REGISTRY.yaml",
    "BLOCKERS.yaml",
    "ARCHITECT-ESCALATIONS",
    "ACCEPTANCE",
    "JOURNEYS",
    "MIGRATION",
    "PROVIDERS",
    "EVIDENCE",
)


def _read_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return value


def _normalized_text_fingerprint(path: Path) -> tuple[str, int]:
    """Fingerprint repository text independently of checkout line endings."""

    text = path.read_bytes().decode("utf-8")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return hashlib.sha256(normalized).hexdigest(), len(normalized)


def _counts(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _percentage(completed: int, total: int) -> int:
    if total <= 0:
        return 0
    return round((completed / total) * 100)


def derive(repo_root: Path) -> dict[str, Any]:
    root = repo_root.resolve()
    implementation = root / "implementation"
    for relative in REQUIRED_CONTROL_PATHS:
        if not (implementation / relative).exists():
            raise ValueError(f"required implementation-control path is missing: {relative}")

    program_state = _read_yaml(implementation / "PROGRAM-STATE.yaml")
    program = program_state["program"]
    dag = _read_yaml(implementation / "MILESTONE-DAG.yaml")
    workstream_registry = _read_yaml(implementation / "WORKSTREAM-REGISTRY.yaml")
    contract_registry = _read_yaml(implementation / "CONTRACT-REGISTRY.yaml")
    blocker_registry = _read_yaml(implementation / "BLOCKERS.yaml")
    journey_registry = _read_yaml(implementation / "JOURNEYS/STATE.yaml")
    migration = _read_yaml(implementation / "MIGRATION/STATE.yaml")
    provider_registry = _read_yaml(implementation / "PROVIDERS/ROLE-CERTIFICATION.yaml")
    current_acceptance_path = implementation / f"ACCEPTANCE/{program['current_milestone']}.yaml"
    acceptance = _read_yaml(
        current_acceptance_path
        if current_acceptance_path.is_file()
        else implementation / "ACCEPTANCE/M0.yaml"
    )
    m0_acceptance = _read_yaml(implementation / "ACCEPTANCE/M0.yaml")

    milestone_states = program_state["milestone_states"]
    milestones = []
    for milestone in dag["milestones"]:
        identifier = milestone["id"]
        state = milestone_states[identifier]
        milestones.append(
            {
                "id": identifier,
                "title": milestone["title"],
                "depends_on": milestone["depends_on"],
                "state": state["state"],
                "started": state["started"],
                "accepted": state["accepted"],
                "mandatory_for_core_ga": milestone["mandatory_for_core_ga"],
            }
        )

    workstreams = workstream_registry["workstreams"]
    blockers = blocker_registry["blockers"]
    adrs = contract_registry["adrs"]
    invariants = contract_registry["invariants"]
    journeys = journey_registry["journeys"]
    providers = provider_registry["providers"]
    evidence = []
    for path in sorted((implementation / "EVIDENCE").iterdir(), key=lambda item: item.name):
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml", ".json"}:
            sha256, byte_count = _normalized_text_fingerprint(path)
            evidence.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256,
                    "bytes": byte_count,
                }
            )

    known_gap_path = implementation / "EVIDENCE/V1-KNOWN-GAPS.yaml"
    if known_gap_path.is_file():
        known_gaps = _read_yaml(known_gap_path)
        regression = {
            "status": known_gaps["status"],
            "reproduced": known_gaps["reproduced"],
            "controlled_baselines": known_gaps["controlled_baselines"],
            "unexpected": known_gaps["unexpected"],
        }
    else:
        regression = {
            "status": "PENDING",
            "reproduced": 0,
            "controlled_baselines": 0,
            "unexpected": [],
        }

    fixture_path = implementation / "MIGRATION/V1-RELEASE-FIXTURE.yaml"
    fixture = _read_yaml(fixture_path) if fixture_path.is_file() else None
    provider_step_states = [state for item in providers for state in item.get("steps", {}).values()]
    accepted = [item["id"] for item in milestones if item["accepted"]]
    ready = [item["id"] for item in milestones if item["state"] == "READY"]
    required_key = f"required_{program['current_milestone'].lower()}"
    required_acceptance = [
        value
        for value in acceptance["evidence_classes"].values()
        if value.get(required_key, False)
    ]
    passing_acceptance = [
        value
        for value in required_acceptance
        if str(value.get("status", "")).startswith("PASS")
    ]
    return {
        "schema_version": "1.0",
        "projection": {
            "authority": "implementation control artifacts",
            "authoritative": False,
            "rebuildable": True,
        },
        "program": program,
        "target_system": program_state["target_system"],
        "summary": {
            "milestones_total": len(milestones),
            "milestones_accepted": len(accepted),
            "program_progress_percent": _percentage(len(accepted), len(milestones)),
            "milestones_started": sum(item["started"] for item in milestones),
            "current_milestone": program["current_milestone"],
            "ready_milestones": ready,
            "active_blockers": len(blockers),
            "workstream_states": _counts([item["state"] for item in workstreams]),
            "adr_count": len(adrs),
            "invariant_count": len(invariants),
            "journey_states": _counts([item["status"] for item in journeys]),
            "provider_step_states": _counts(provider_step_states),
            "evidence_items": len(evidence),
            "acceptance_classes_required": len(required_acceptance),
            "acceptance_classes_passing": len(passing_acceptance),
            "current_milestone_progress_percent": _percentage(
                len(passing_acceptance), len(required_acceptance)
            ),
        },
        "milestones": milestones,
        "workstreams": workstreams,
        "blockers": blockers,
        "observations": blocker_registry.get("observations", []),
        "adrs": adrs,
        "invariants": invariants,
        "providers": {
            "schema_validation": provider_registry["schema_validation"],
            "roles": providers,
        },
        "journeys": journeys,
        "acceptance": acceptance,
        "m0_acceptance": m0_acceptance,
        "migration": migration,
        "v1_release_fixture": (
            {
                "fixture_id": fixture["fixture_id"],
                "source_ref": fixture["source_ref"],
                "source_commit": fixture["source_commit"],
                "file_count": fixture["file_count"],
                "aggregate_sha256": fixture["aggregate_sha256"],
            }
            if fixture
            else {"status": "PENDING"}
        ),
        "v1_regression": regression,
        "evidence": evidence,
    }


def render_current_state(state: dict[str, Any]) -> str:
    program = state["program"]
    summary = state["summary"]
    current = next(
        item for item in state["milestones"] if item["id"] == program["current_milestone"]
    )
    accepted = [item["id"] for item in state["milestones"] if item["accepted"]]
    ready = summary["ready_milestones"]
    active = [item["id"] for item in state["workstreams"] if item["state"] == "IN_PROGRESS"]
    lines = [
        "# ARTIFEX 2.0 Implementation Current State",
        "",
        "> Generated from machine-readable implementation-control artifacts. This file is a projection,",
        "> not independent status authority.",
        "",
        "## Program",
        "",
        f"- Target release: `{program['target_release']}`",
        f"- Handoff: `{program['handoff_id']}`",
        f"- Intake baseline: `{program['intake_commit']}`",
        f"- Branch: `{program['branch']}`",
        f"- Current milestone: `{program['current_milestone']}`",
        f"- Current status: `{program['current_status']}`",
        f"- Accepted milestones: `{', '.join(accepted) if accepted else 'none'}`",
        f"- Ready milestones: `{', '.join(ready) if ready else 'none'}`",
        f"- Latest accepted commit: `{program['latest_accepted_commit']}`",
        f"- Next integration point: `{program['next_integration_point']}`",
        f"- {program['current_milestone']} started: `{str(current['started']).lower()}`",
        "",
        "## Work",
        "",
        f"- Active workstreams: `{', '.join(active) if active else 'none'}`",
        f"- Active blockers: `{summary['active_blockers']}`",
        f"- Dashboard state: `{program.get('dashboard_state', 'see PROGRAM-STATE.yaml')}`",
        f"- V1 regression state: `{state['v1_regression']['status']}`",
        f"- Migration state: `{state['migration']['fixture_state']}`",
        "",
        "## Acceptance",
        "",
        f"- {program['current_milestone']} verdict: `{state['acceptance']['verdict']}`",
        f"- Mandatory work complete: `{str(state['acceptance']['mandatory_work_complete']).lower()}`",
        "- Mandatory journeys: `"
        + (", ".join(state["acceptance"]["mandatory_journeys"]) or "none")
        + "`",
        f"- Next integration point: `{program['next_integration_point']}`",
        "",
    ]
    return "\n".join(lines)


def _table(headers: list[str], rows: list[list[object]]) -> str:
    head = "".join(f"<th>{html.escape(str(value))}</th>" for value in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(state: dict[str, Any]) -> str:
    summary = state["summary"]
    program = state["program"]
    target = state["target_system"]
    glossary = _table(
        ["Term", "Meaning"],
        [[key, value] for key, value in target["glossary"].items()],
    )
    milestones = _table(
        ["ID", "Milestone", "State", "Depends on"],
        [
            [item["id"], item["title"], item["state"], ", ".join(item["depends_on"]) or "none"]
            for item in state["milestones"]
        ],
    )
    workstreams = _table(
        ["ID", "Purpose", "Owner", "State", "Branch"],
        [
            [item["id"], item["purpose"], item["owner_subagent"], item["state"], item["branch"]]
            for item in state["workstreams"]
        ],
    )
    adrs = _table(
        ["Contract", "Title", "Frozen", "M0 baseline"],
        [
            [item["id"], item["title"], item["frozen_at"], item["m0_baseline_state"]]
            for item in state["adrs"]
        ],
    )
    invariants = _table(
        ["Invariant", "Title", "M0 baseline", "Implementation"],
        [
            [item["id"], item["title"], item["m0_baseline_state"], item["implementation_state"]]
            for item in state["invariants"]
        ],
    )
    providers = _table(
        ["Provider", "Role", "Requirement", "Certified"],
        [
            [
                item["provider"],
                item["role"],
                item["requirement"],
                item["steps"]["LIVE_ROLE_CERTIFIED"],
            ]
            for item in state["providers"]["roles"]
        ],
    )
    journeys = _table(
        ["Journey", "Title", "State", "Environment"],
        [
            [item["id"], item["title"], item["status"], item["environment"] or "not run"]
            for item in state["journeys"]
        ],
    )
    acceptance = _table(
        [
            "Evidence class",
            f"Required in {program['current_milestone']}",
            "Status",
            "Evidence",
        ],
        [
            [
                name,
                value.get(f"required_{program['current_milestone'].lower()}", False),
                value["status"],
                ", ".join(value["evidence"]) or "none",
            ]
            for name, value in state["acceptance"]["evidence_classes"].items()
        ],
    )
    evidence = _table(
        ["Evidence", "SHA-256", "Bytes"],
        [[item["path"], item["sha256"], item["bytes"]] for item in state["evidence"]],
    )
    embedded = json.dumps(state, sort_keys=True, ensure_ascii=False).replace("</", "<\\/")
    cards = "".join(
        f'<article class="card"><span>{html.escape(label)}</span><strong>{value}</strong></article>'
        for label, value in (
            ("Current milestone", program["current_milestone"]),
            ("Accepted", f"{summary['milestones_accepted']}/{summary['milestones_total']}"),
            ("Active blockers", summary["active_blockers"]),
            ("ADRs captured", summary["adr_count"]),
            ("Invariants captured", summary["invariant_count"]),
            ("Evidence items", summary["evidence_items"]),
        )
    )
    progress = "".join(
        f'''<article class="progress-item"><div><span>{html.escape(label)}</span><strong>{percent}%</strong></div>
<div class="progress-track" role="progressbar" aria-label="{html.escape(label)}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{percent}"><span style="width:{percent}%"></span></div>
<small>{html.escape(detail)}</small></article>'''
        for label, percent, detail in (
            (
                "Program progress",
                summary["program_progress_percent"],
                f"{summary['milestones_accepted']} of {summary['milestones_total']} milestones accepted",
            ),
            (
                f"{program['current_milestone']} evidence progress",
                summary["current_milestone_progress_percent"],
                f"{summary['acceptance_classes_passing']} of {summary['acceptance_classes_required']} required evidence classes passing",
            ),
        )
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARTIFEX 2.0 implementation dashboard</title>
<style>
:root{{--ink:#eaf2ff;--muted:#9fb0c9;--panel:#101a2b;--line:#263752;--accent:#74d3ae;--warn:#ffcc66}}
*{{box-sizing:border-box}}body{{margin:0;background:#07101d;color:var(--ink);font:15px/1.5 system-ui,sans-serif}}
header,main{{max-width:1500px;margin:auto;padding:24px}}header{{border-bottom:1px solid var(--line)}}
.eyebrow{{color:var(--accent);letter-spacing:.12em;text-transform:uppercase}}h1{{margin:.2rem 0;font-size:clamp(2rem,5vw,4rem)}}
.notice{{color:var(--warn)}}nav{{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}}nav a{{color:var(--ink);border:1px solid var(--line);padding:6px 10px;border-radius:999px;text-decoration:none}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0}}.card,section{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}}
.card span{{display:block;color:var(--muted)}}.card strong{{display:block;font-size:1.7rem;margin-top:5px}}section{{margin:18px 0;overflow:auto}}h2{{margin-top:0}}table{{border-collapse:collapse;width:100%;min-width:720px}}th,td{{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{color:var(--accent)}}code{{color:#b9d8ff}}.meta{{color:var(--muted)}}
.progress-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin:0 0 24px}}.progress-item{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}}.progress-item>div:first-child{{display:flex;align-items:baseline;justify-content:space-between;gap:16px}}.progress-item span,.progress-item small{{color:var(--muted)}}.progress-item strong{{font-size:1.7rem}}.progress-track{{height:12px;margin:12px 0 8px;background:#07101d;border:1px solid var(--line);border-radius:999px;overflow:hidden}}.progress-track>span{{display:block;height:100%;background:linear-gradient(90deg,var(--accent),#82b7ff);border-radius:inherit}}
</style></head><body>
<header><div class="eyebrow">Implementation control projection · {html.escape(program['current_milestone'])}</div><h1>ARTIFEX 2.0</h1>
<p>{html.escape(target["overview"])}</p><p class="notice">Derived view only. Machine-readable implementation-control artifacts remain authority.</p>
<nav>{"".join(f'<a href="#{item}">{item}</a>' for item in ("overview", "milestones", "workstreams", "contracts", "providers", "journeys", "acceptance", "migration", "evidence"))}</nav></header>
<main><div class="cards">{cards}</div><div class="progress-grid">{progress}</div>
<section id="overview"><h2>Target system and glossary</h2><p>Standalone baseline: {html.escape(" · ".join(target["standalone_baseline"]))}</p>{glossary}</section>
<section id="milestones"><h2>Milestone DAG and progress</h2>{milestones}</section>
<section id="workstreams"><h2>Workstreams, ownership and blockers</h2><p>Active blockers: <strong>{summary["active_blockers"]}</strong></p>{workstreams}</section>
<section id="contracts"><h2>Frozen ADR state</h2>{adrs}<h2>Invariant conformance baseline</h2>{invariants}</section>
<section id="providers"><h2>Provider role certification</h2><p>Schema validation: <code>{state["providers"]["schema_validation"]}</code></p>{providers}</section>
<section id="journeys"><h2>Outcome journeys J01-J20</h2>{journeys}</section>
<section id="acceptance"><h2>{html.escape(program['current_milestone'])} acceptance evidence classes</h2>{acceptance}</section>
<section id="migration"><h2>Migration and V1 regression</h2><pre>{html.escape(json.dumps({"migration": state["migration"], "fixture": state["v1_release_fixture"], "regression": state["v1_regression"]}, indent=2, sort_keys=True))}</pre></section>
<section id="evidence"><h2>Evidence links and fingerprints</h2>{evidence}</section>
<p class="meta">Baseline <code>{program["intake_commit"]}</code> · release target <code>{program["target_release"]}</code></p>
</main><script id="artifex-implementation-state" type="application/json">{embedded}</script></body></html>
"""


def render(repo_root: Path, *, write: bool) -> dict[str, Any]:
    root = repo_root.resolve()
    state = derive(root)
    outputs = {
        root / "implementation/CURRENT-STATE.md": render_current_state(state),
        root / "implementation/dashboard/state.json": json.dumps(
            state, indent=2, sort_keys=True, ensure_ascii=False
        )
        + "\n",
        root / "implementation/dashboard/index.html": render_html(state),
    }
    stale = []
    for path, content in outputs.items():
        normalized = content.replace("\r\n", "\n")
        if write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(normalized, encoding="utf-8", newline="\n")
        elif not path.is_file() or path.read_text(encoding="utf-8") != normalized:
            stale.append(path.relative_to(root).as_posix())
    if stale:
        raise ValueError(f"generated implementation projections are stale: {', '.join(stale)}")
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args()
    state = render(arguments.repo_root, write=arguments.write)
    summary = state["summary"]
    print(
        "implementation-dashboard=PASS "
        f"milestones={summary['milestones_total']} adrs={summary['adr_count']} "
        f"invariants={summary['invariant_count']} evidence={summary['evidence_items']}"
    )


if __name__ == "__main__":
    main()
