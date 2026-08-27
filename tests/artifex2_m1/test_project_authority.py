from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from artifex.compilation._util import model_fingerprint
from artifex.project import (
    ArtifactCorruptError,
    ProjectAuthority,
    ProjectRepository,
    SemanticConflictError,
)


def _changed(authority: ProjectAuthority, description: str):  # type: ignore[no-untyped-def]
    current = authority.current().model
    return replace(current, project=replace(current.project, description=description))


@pytest.mark.integration
def test_only_project_authority_accepts_external_semantic_mutation(tmp_path: Path) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="project-1", name="One")
    authority = ProjectAuthority.bootstrap(
        repository, accepted_at="2026-08-27T00:00:00Z"
    )
    accepted = authority.current()

    repository.save(_changed(authority, "external edit"))

    assert authority.current() == accepted
    proposal = authority.observe_external_mutation(actor="observer")
    assert proposal is not None
    assert proposal.source == "EXTERNAL_REPOSITORY_MUTATION"
    assert authority.current().number == 1

    revision = authority.accept(
        proposal.id,
        expected_revision=1,
        actor="project-authority",
        accepted_at="2026-08-27T00:01:00Z",
    )
    assert revision.number == 2
    assert revision.model.project.description == "external edit"


@pytest.mark.integration
def test_optimistic_revision_conflict_prevents_lost_update(tmp_path: Path) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="project-1", name="One")
    authority = ProjectAuthority.bootstrap(repository)
    first = authority.propose(
        _changed(authority, "first"),
        expected_revision=1,
        actor="session-a",
        proposal_id="proposal-a",
    )
    second = authority.propose(
        _changed(authority, "second"),
        expected_revision=1,
        actor="session-b",
        proposal_id="proposal-b",
    )

    authority.accept(first.id, expected_revision=1, actor="project-authority")
    with pytest.raises(SemanticConflictError, match="current 2"):
        authority.accept(second.id, expected_revision=1, actor="project-authority")

    assert authority.current().number == 2
    assert authority.current().model.project.description == "first"


@pytest.mark.unit
def test_revision_chain_fails_closed_when_portable_record_is_tampered(tmp_path: Path) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="project-1", name="One")
    authority = ProjectAuthority.bootstrap(repository)
    target = tmp_path / ".artifex" / "semantic-revisions" / "00000000000000000001.json"
    value = json.loads(target.read_text(encoding="utf-8"))
    value["fingerprint"] = "0" * 64
    target.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ArtifactCorruptError, match="invalid semantic revision"):
        authority.current()


@pytest.mark.integration
def test_accepted_revision_fingerprint_is_the_portable_v1_model_fingerprint(
    tmp_path: Path,
) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="v1-project", name="V1")
    expected = model_fingerprint(repository.load().to_dict())

    authority = ProjectAuthority.bootstrap(repository, source="V1_MODEL_ADAPTER")

    assert authority.current().fingerprint == expected
    assert authority.current().proposal_id == "V1_MODEL_ADAPTER"
