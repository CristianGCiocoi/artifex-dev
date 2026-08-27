"""Consent-gated integration setup in ARTIFEX-owned state only."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from artifex.distribution.approvals import ApprovalStore
from artifex.distribution.models import DecisionExplanation, SetupAction, SetupPlan
from artifex.distribution.presentation import explain_decision, require_approval

SUPPORTED_INTEGRATIONS = frozenset({"manual", "hermes", "codex", "claude"})
SETUP_STATE_PATH = ".artifex/integrations.json"


def plan_integration_setup(
    project_root: str | Path,
    integration_ids: tuple[str, ...],
    *,
    provider_specs: Sequence[Mapping[str, Any]] = (),
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
    specs = _normalize_provider_specs(selected, provider_specs)
    actions = tuple(
        SetupAction(
            identifier,
            SETUP_STATE_PATH,
            "record opt-in in project-owned ARTIFEX configuration",
            provider_configuration=specs[identifier],
        )
        for identifier in selected
    )
    decision = _setup_decision(
        root,
        selected,
        specs,
        approval_store=approval_store,
        issue_token=issue_token,
    )
    return SetupPlan(str(root), actions, decision)


def _setup_decision(
    root: Path,
    selected: tuple[str, ...],
    provider_specs: Mapping[str, Mapping[str, Any]],
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
            "provider_specs": [provider_specs[key] for key in sorted(provider_specs)],
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
    specs = {
        action.integration_id: dict(action.provider_configuration or {})
        for action in plan.actions
    }
    expected = _setup_decision(
        root,
        selected,
        specs,
        approval_store=approval_store,
        issue_token=False,
    )
    if expected.plan_fingerprint != plan.decision.plan_fingerprint:
        raise PermissionError("setup plan was modified after approval was issued")
    require_approval(expected, confirmation_token, approval_store=approval_store)
    target = root / SETUP_STATE_PATH
    if target.resolve() != target or root not in target.parents:
        raise ValueError("setup state must remain inside the project root")
    target.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "schema_version": "2.0",
        "authority": "ARTIFEX_PROJECT_STATE",
        "vendor_configuration_mutated": False,
        "enabled": [action.integration_id for action in plan.actions],
        "providers": [specs[action.integration_id] for action in plan.actions],
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


def _normalize_provider_specs(
    selected: tuple[str, ...], provider_specs: Sequence[Mapping[str, Any]]
) -> dict[str, Mapping[str, Any]]:
    supplied: dict[str, Mapping[str, Any]] = {}
    for raw in provider_specs:
        provider_id = raw.get("provider_id")
        if not isinstance(provider_id, str) or not provider_id:
            raise ValueError("provider spec requires provider_id")
        if provider_id in supplied:
            raise ValueError(f"duplicate provider spec: {provider_id}")
        supplied[provider_id] = _normalize_provider_spec(raw)
    if set(supplied) - set(selected):
        raise ValueError("provider specs must match selected integrations")
    return {
        identifier: supplied.get(identifier, _default_provider_spec(identifier))
        for identifier in selected
    }


def _normalize_provider_spec(value: Mapping[str, Any]) -> Mapping[str, Any]:
    allowed = {
        "provider_id",
        "enabled",
        "roles",
        "governance_mode",
        "command",
        "credential_reference",
    }
    if set(value) - allowed:
        raise ValueError("provider spec contains unknown fields")
    provider_id = _required_text(value.get("provider_id"), "provider_id")
    command = _required_text_array(value.get("command"), "command")
    roles = _required_text_array(
        value.get("roles", _default_roles(provider_id)), "roles"
    )
    enabled = value.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("provider enabled must be a boolean")
    governance_mode = _required_text(
        value.get("governance_mode", "STANDALONE"), "governance_mode"
    )
    reference_value = value.get("credential_reference")
    reference = (
        _normalize_credential_reference(reference_value, provider_id)
        if reference_value is not None
        else None
    )
    return {
        "provider_id": provider_id,
        "enabled": enabled,
        "roles": list(roles),
        "governance_mode": governance_mode,
        "command": list(command),
        "credential_reference": reference,
    }


def _normalize_credential_reference(value: object, provider_id: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("credential_reference must be an object")
    if set(value) - {"broker", "reference", "provider_id", "scopes"}:
        raise ValueError("credential_reference contains unknown fields")
    observed = _required_text(value.get("provider_id", provider_id), "credential provider_id")
    if observed != provider_id:
        raise ValueError("credential reference provider does not match provider spec")
    return {
        "broker": _required_text(value.get("broker"), "credential broker"),
        "reference": _required_text(value.get("reference"), "credential reference"),
        "provider_id": provider_id,
        "scopes": list(_required_text_array(value.get("scopes"), "credential scopes")),
    }


def _default_provider_spec(provider_id: str) -> Mapping[str, Any]:
    reference: Mapping[str, Any] | None = None
    if provider_id == "codex":
        reference = {
            "broker": "codex-native-session",
            "reference": "default",
            "provider_id": "codex",
            "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        }
    return {
        "provider_id": provider_id,
        "enabled": True,
        "roles": list(_default_roles(provider_id)),
        "governance_mode": "STANDALONE",
        "command": [provider_id],
        "credential_reference": reference,
    }


def _default_roles(provider_id: str) -> tuple[str, ...]:
    if provider_id in {"codex", "claude"}:
        return ("INTERACTION", "EXECUTION_IMPLEMENTER")
    if provider_id == "manual":
        return ("INTERACTION", "EXECUTION_IMPLEMENTER")
    return ("INTERACTION",)


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _required_text_array(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be an array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{name} must contain non-empty strings")
    result = tuple(str(item) for item in value)
    if not result:
        raise ValueError(f"{name} cannot be empty")
    return result
