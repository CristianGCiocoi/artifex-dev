"""Promotion, privilege-safe overlay preview, and divergence inspection."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from artifex.policy import PrivilegePolicy

from .model import (
    CandidateOverlay,
    KnowledgeItem,
    KnowledgeScope,
    KnowledgeState,
    OverlayValidationStatus,
    Sensitivity,
)


class PromotionDeniedError(ValueError):
    """Raised when knowledge has insufficient authority/evidence for promotion."""


class OverlayPrivilegeError(PermissionError):
    """Raised when overlay privileges are absent, undeclared, or expanded."""


_SENSITIVITY_RANK = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.SENSITIVE: 2,
    Sensitivity.RESTRICTED: 3,
}


def promote_knowledge(
    item: KnowledgeItem,
    target: KnowledgeScope,
    *,
    evidence: tuple[str, ...],
    independently_validated: bool,
    project_id: str | None = None,
) -> KnowledgeItem:
    """Promote one adjacent scope after explicit policy evaluation.

    INSTANCE promotion has a mechanical stronger-evidence floor even when an
    item's local policy is weaker.  V1 never promotes to PROFILE or CORE.
    """

    adjacent = {
        KnowledgeScope.RUN: KnowledgeScope.PROJECT,
        KnowledgeScope.HARNESS: KnowledgeScope.PROJECT,
        KnowledgeScope.PROJECT: KnowledgeScope.INSTANCE,
    }
    if adjacent.get(item.scope) is not target:
        raise PromotionDeniedError(f"promotion {item.scope.value}->{target.value} is not allowed")
    policy = item.promotion_policy
    if target not in policy.allowed_targets:
        raise PromotionDeniedError("target is excluded by the item's promotion policy")
    if item.state is not KnowledgeState.CURRENT:
        raise PromotionDeniedError("only CURRENT knowledge may be promoted")
    if item.confidence < policy.minimum_confidence:
        raise PromotionDeniedError("knowledge confidence is below the promotion threshold")
    required_evidence = max(policy.minimum_evidence, 2 if target is KnowledgeScope.INSTANCE else 1)
    if len(set(evidence)) < required_evidence:
        raise PromotionDeniedError(
            f"promotion requires at least {required_evidence} evidence items"
        )
    if policy.require_validation and not independently_validated:
        raise PromotionDeniedError("promotion requires independent validation")
    if _SENSITIVITY_RANK[item.sensitivity] > _SENSITIVITY_RANK[policy.maximum_sensitivity]:
        raise PromotionDeniedError("knowledge sensitivity exceeds its promotion ceiling")
    if item.sensitivity is Sensitivity.RESTRICTED:
        raise PromotionDeniedError("RESTRICTED knowledge cannot be promoted in V1")
    if target is KnowledgeScope.PROJECT and not (project_id or item.project_id):
        raise PromotionDeniedError("PROJECT promotion requires an explicit project_id")
    return replace(
        item,
        scope=target,
        project_id=(project_id or item.project_id) if target is KnowledgeScope.PROJECT else None,
        run_id=None,
        promoted_from=item.scope,
    )


@dataclass(frozen=True, slots=True)
class DivergenceReport:
    effective_configuration: Mapping[str, Any]
    overlay_ids: tuple[str, ...]
    changed_paths: tuple[str, ...]
    core_unchanged: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "effective_configuration": dict(self.effective_configuration),
            "overlay_ids": list(self.overlay_ids),
            "changed_paths": list(self.changed_paths),
            "core_unchanged": self.core_unchanged,
        }


def inspect_divergence(
    core_configuration: Mapping[str, Any],
    overlays: tuple[CandidateOverlay, ...],
    *,
    privilege_policy: PrivilegePolicy | None,
) -> DivergenceReport:
    """Preview effective configuration without mutating the supplied Core value.

    Privilege authority is deliberately not defaulted.  Every overlay must
    declare its permissions and an explicit policy must authorize the complete
    set, including the empty set.  This keeps callers from accidentally
    bypassing the ceiling during preview or activation code added later.
    """

    if privilege_policy is None:
        raise OverlayPrivilegeError("an explicit privilege policy is required (fail closed)")
    before = copy.deepcopy(dict(core_configuration))
    effective: dict[str, Any] = copy.deepcopy(before)
    paths: list[str] = []
    identifiers: set[str] = set()
    for overlay in overlays:
        if overlay.id in identifiers:
            raise ValueError(f"duplicate overlay identifier: {overlay.id}")
        identifiers.add(overlay.id)
        if overlay.validation_status is not OverlayValidationStatus.PASSED:
            raise ValueError(f"overlay is not validated: {overlay.id}")
        requested = set(overlay.requested_privileges)
        if not privilege_policy.permits_overlay(requested):
            raise OverlayPrivilegeError(f"overlay expands privileges: {overlay.id}")
        paths.extend(_merge(effective, overlay.changes))
    return DivergenceReport(
        effective_configuration=effective,
        overlay_ids=tuple(overlay.id for overlay in overlays),
        changed_paths=tuple(sorted(set(paths))),
        core_unchanged=dict(core_configuration) == before,
    )


def _merge(target: dict[str, Any], changes: Mapping[str, Any], prefix: str = "") -> list[str]:
    paths: list[str] = []
    for key, value in changes.items():
        if not isinstance(key, str) or not key:
            raise ValueError("overlay change keys must be non-empty strings")
        path = f"{prefix}.{key}" if prefix else key
        existing = target.get(key)
        if isinstance(existing, dict) and isinstance(value, Mapping):
            paths.extend(_merge(existing, value, path))
        else:
            target[key] = copy.deepcopy(value)
            paths.append(path)
    return paths
