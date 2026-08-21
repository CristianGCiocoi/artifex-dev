"""Experience-mode projection and risk-aware approval explanations."""

from __future__ import annotations

import hashlib

from artifex.distribution.models import DecisionExplanation, ExperienceMode, RiskLevel

_POLICY: dict[ExperienceMode, dict[str, object]] = {
    ExperienceMode.BEGINNER: {
        "detail": "plain-language",
        "show_internal_ids": False,
        "show_raw_contracts": False,
        "guided_defaults": True,
    },
    ExperienceMode.GUIDED: {
        "detail": "explained-technical",
        "show_internal_ids": True,
        "show_raw_contracts": False,
        "guided_defaults": True,
    },
    ExperienceMode.EXPERT: {
        "detail": "complete",
        "show_internal_ids": True,
        "show_raw_contracts": True,
        "guided_defaults": False,
    },
}


def presentation_policy(mode: ExperienceMode | str) -> dict[str, object]:
    selected = ExperienceMode(mode)
    return {"mode": selected.value, **_POLICY[selected]}


def explain_decision(
    action: str,
    risk: RiskLevel | str,
    *,
    effects: tuple[str, ...],
    rollback: str,
) -> DecisionExplanation:
    if not action.strip() or not effects or not rollback.strip():
        raise ValueError("action, effects, and rollback are required")
    level = RiskLevel(risk)
    approval = level is not RiskLevel.READ_ONLY
    token = None
    if approval:
        digest = hashlib.sha256(
            (action + "\0" + "\0".join(effects) + "\0" + rollback).encode("utf-8")
        ).hexdigest()[:12]
        token = f"approve-{digest}"
    return DecisionExplanation(action, level, effects, rollback, approval, token)


def require_approval(decision: DecisionExplanation, supplied_token: str | None) -> None:
    if decision.approval_required and supplied_token != decision.confirmation_token:
        raise PermissionError(
            f"explicit approval required; use confirmation token {decision.confirmation_token}"
        )
