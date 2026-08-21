"""A zero-hand-configuration beginner entry into the canonical Project Model."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artifex.distribution.models import ExperienceMode
from artifex.distribution.presentation import presentation_policy
from artifex.project import ProjectRepository


@dataclass(frozen=True, slots=True)
class BeginnerJourneyResult:
    project_root: str
    project_id: str
    intent: str
    lifecycle: str
    workflow_depth: str
    next_step: str
    canonical_authority: str = ".artifex/project-model.json"
    manual_configuration_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_root": self.project_root,
            "project_id": self.project_id,
            "intent": self.intent,
            "lifecycle": self.lifecycle,
            "workflow_depth": self.workflow_depth,
            "next_step": self.next_step,
            "canonical_authority": self.canonical_authority,
            "manual_configuration_required": self.manual_configuration_required,
            "presentation": presentation_policy(ExperienceMode.BEGINNER),
        }


def start_beginner_journey(
    project_root: str | Path,
    intent: str,
    *,
    project_name: str | None = None,
) -> BeginnerJourneyResult:
    requested = intent.strip()
    if not requested:
        raise ValueError("tell ARTIFEX what you want to build")
    root = Path(project_root).resolve()
    name = (project_name or root.name or "My Project").strip()
    project_id = _slug(name)
    model_path = root / ".artifex" / "project-model.json"
    if model_path.exists():
        repository = ProjectRepository(root)
        model = repository.load()
    else:
        repository = ProjectRepository.initialize(
            root,
            project_id=project_id,
            name=name,
            description=requested,
        )
        model = repository.load()
    return BeginnerJourneyResult(
        str(root),
        model.project.id,
        requested,
        model.project.lifecycle.value,
        model.project.workflow_depth.value,
        "Review the captured intent, then let ARTIFEX prepare the governed idea stage.",
    )


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug or "artifex-project"
