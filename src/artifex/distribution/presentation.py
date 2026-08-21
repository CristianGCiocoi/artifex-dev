"""Experience-mode projection and risk-aware approval explanations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from artifex.distribution.approvals import ApprovalStore, consume_decision, issue_decision
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
    binding: Mapping[str, Any] | None = None,
    approval_store: ApprovalStore | None = None,
    issue_token: bool = True,
    now: datetime | None = None,
    ttl_seconds: int = 600,
) -> DecisionExplanation:
    return issue_decision(
        action,
        risk,
        effects=effects,
        rollback=rollback,
        binding=binding,
        approval_store=approval_store,
        issue_token=issue_token,
        now=now,
        ttl_seconds=ttl_seconds,
    )


def require_approval(
    decision: DecisionExplanation,
    supplied_token: str | None,
    *,
    approval_store: ApprovalStore | None = None,
    now: datetime | None = None,
) -> None:
    consume_decision(decision, supplied_token, approval_store=approval_store, now=now)
