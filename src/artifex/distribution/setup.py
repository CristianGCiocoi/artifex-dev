"""Consent-gated integration setup in ARTIFEX-owned state only."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from artifex.distribution.approvals import ApprovalStore
from artifex.distribution.models import DecisionExplanation, SetupAction, SetupPlan
from artifex.distribution.presentation import explain_decision, require_approval

SUPPORTED_INTEGRATIONS = frozenset({"manual", "hermes", "codex", "claude"})
SETUP_STATE_PATH = ".artifex/integrations.json"


def plan_integration_setup(
    project_root: str | Path,
    integration_ids: tuple[str, ...],
    *,
    approval_store: ApprovalStore | None = None,
    issue_token: bool = True,
) -> SetupPlan:
    root = Path(project_root).resolve()
    selected = tuple(dict.fromkeys(integration_ids))
    if not selected:
        selected = ("manual",)
    unknown = set(selected) - SUPPORTED_INTEGRATIONS
    if unknown:
        raise ValueError(f"unsupported integrations: {', '.join(sorted(unknown))}")
    actions = tuple(
        SetupAction(
            identifier,
            SETUP_STATE_PATH,
            "record opt-in in project-owned ARTIFEX configuration",
        )
        for identifier in selected
    )
    decision = _setup_decision(
        root,
        selected,
        approval_store=approval_store,
        issue_token=issue_token,
    )
    return SetupPlan(str(root), actions, decision)


def _setup_decision(
    root: Path,
    selected: tuple[str, ...],
    *,
    approval_store: ApprovalStore | None,
    issue_token: bool,
) -> DecisionExplanation:
    return explain_decision(
        "configure integrations",
        "REVERSIBLE",
        effects=(f"write {root / SETUP_STATE_PATH}",),
        rollback=f"restore or remove {root / SETUP_STATE_PATH}",
        binding={
            "project_root": str(root),
            "integration_ids": list(selected),
            "state_path": SETUP_STATE_PATH,
        },
        approval_store=approval_store,
        issue_token=issue_token,
    )


def apply_integration_setup(
    plan: SetupPlan,
    *,
    confirmation_token: str | None,
    approval_store: ApprovalStore | None = None,
) -> SetupPlan:
    root = Path(plan.project_root).resolve()
    selected = tuple(action.integration_id for action in plan.actions)
    expected = _setup_decision(
        root, selected, approval_store=approval_store, issue_token=False
    )
    if expected.plan_fingerprint != plan.decision.plan_fingerprint:
        raise PermissionError("setup plan was modified after approval was issued")
    require_approval(expected, confirmation_token, approval_store=approval_store)
    target = root / SETUP_STATE_PATH
    if target.resolve() != target or root not in target.parents:
        raise ValueError("setup state must remain inside the project root")
    target.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "schema_version": "1.0",
        "authority": "ARTIFEX_PROJECT_STATE",
        "vendor_configuration_mutated": False,
        "enabled": [action.integration_id for action in plan.actions],
    }
    _write_json_atomic(target, value)
    return SetupPlan(plan.project_root, plan.actions, plan.decision, applied=True)


def _write_json_atomic(path: Path, value: object) -> None:
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
