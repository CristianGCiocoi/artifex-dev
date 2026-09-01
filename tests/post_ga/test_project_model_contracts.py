from __future__ import annotations

from dataclasses import replace

import pytest

from artifex.ids import StableId
from artifex.project.git import GitState
from artifex.project.model import (
    Artifact,
    ArtifactStatus,
    EntityKind,
    KnowledgeAdoptionProvenance,
    LifecycleContribution,
    LifecycleStage,
    ProjectGovernanceState,
    ProjectInfo,
    ProjectKnowledgeAdoption,
    ProjectLifecycle,
    ProjectModel,
    ProjectResearchAdoption,
    Provenance,
    StructuredEntity,
)


def _artifact(identifier: str = "ART-ONE", path: str = "docs/one.md") -> Artifact:
    return Artifact(
        StableId.parse(identifier),
        "document",
        path,
        ArtifactStatus.ACCEPTED,
        "a" * 64,
        provenance=Provenance(path, "b" * 40),
    )


def _research() -> ProjectResearchAdoption:
    return ProjectResearchAdoption(
        "pandora",
        "RESEARCH",
        "pandora-public",
        "1.0",
        "a" * 64,
        "request-1",
        "bundle-1",
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        ("finding",),
        ("https://example.invalid/source",),
        "researcher",
        "2026-09-01T00:00:00Z",
    )


def _knowledge() -> ProjectKnowledgeAdoption:
    return ProjectKnowledgeAdoption(
        "knowledge-1",
        "recommendation-1",
        "Retain durable evidence.",
        "source-project",
        1,
        "a" * 64,
        "lesson-1",
        (
            KnowledgeAdoptionProvenance(
                "organizational-store", "2026-09-01T00:00:00Z", commit="b" * 40
            ),
        ),
        0.9,
        ("project-contract",),
        ("evidence",),
        ("runtime",),
        "2027-09-01T00:00:00Z",
        "c" * 64,
        ("d" * 64,),
        "validator",
        "architect",
        "review",
        "ACCEPT",
        "project-owner",
        "2026-09-01T00:00:00Z",
    )


@pytest.mark.unit
def test_governance_history_is_complete_and_monotonic() -> None:
    with pytest.raises(ValueError, match="summary"):
        LifecycleContribution(LifecycleStage.EXPLORATION, "", "actor", "session")
    with pytest.raises(ValueError, match="references"):
        LifecycleContribution(
            LifecycleStage.EXPLORATION, "explore", "actor", "session", ("",)
        )
    exploration = LifecycleContribution(
        LifecycleStage.EXPLORATION, "explore", "actor", "session", ("evidence-1",)
    )
    state = ProjectGovernanceState().advance(exploration)
    assert ProjectGovernanceState.from_dict(state.to_dict()) == state
    with pytest.raises(ValueError, match="one stage"):
        state.advance(
            LifecycleContribution(LifecycleStage.ARCHITECTURE, "skip", "actor", "session")
        )
    with pytest.raises(ValueError, match="monotonic"):
        ProjectGovernanceState(
            LifecycleStage.EXPLORATION,
            (
                LifecycleContribution(
                    LifecycleStage.RESEARCH, "research", "actor", "session"
                ),
                exploration,
            ),
        )
    with pytest.raises(ValueError, match="latest contribution"):
        ProjectGovernanceState(LifecycleStage.RESEARCH, (exploration,))


@pytest.mark.unit
def test_knowledge_provenance_and_adoption_are_durably_bound() -> None:
    with pytest.raises(ValueError, match="source and time"):
        KnowledgeAdoptionProvenance("", "now", commit="a")
    with pytest.raises(ValueError, match="durable reference"):
        KnowledgeAdoptionProvenance("source", "now")
    provenance = KnowledgeAdoptionProvenance(
        "source", "now", artifact="record.json", evidence_ids=("evidence-1",)
    )
    assert KnowledgeAdoptionProvenance.from_dict(provenance.to_dict()) == provenance

    adoption = _knowledge()
    assert ProjectKnowledgeAdoption.from_dict(adoption.to_dict()) == adoption
    for changes, message in (
        ({"statement": ""}, "fields"),
        ({"provenance": ()}, "retain provenance"),
        ({"confidence": 1.1}, "confidence"),
        ({"source_project_revision": 0}, "revision"),
        ({"source_project_fingerprint": "bad"}, "fingerprint"),
        ({"record_digest": "bad"}, "digest"),
        ({"evidence_digests": ()}, "evidence digests"),
    ):
        with pytest.raises(ValueError, match=message):
            replace(adoption, **changes)


@pytest.mark.unit
def test_research_adoption_requires_pandora_authority_and_canonical_bindings() -> None:
    adoption = _research()
    assert ProjectResearchAdoption.from_dict(adoption.to_dict()) == adoption
    for changes, message in (
        ({"request_id": ""}, "identity"),
        ({"provider_id": "other"}, "Pandora"),
        ({"provider_role": "EXECUTION"}, "Pandora"),
        ({"request_sha256": "bad"}, "SHA-256"),
        ({"findings": ()}, "findings"),
        ({"source_uris": ()}, "source provenance"),
    ):
        with pytest.raises(ValueError, match=message):
            replace(adoption, **changes)
    value = adoption.to_dict()
    value["authority"] = "PANDORA"
    with pytest.raises(ValueError, match="semantic authority"):
        ProjectResearchAdoption.from_dict(value)


@pytest.mark.unit
def test_artifact_entity_and_project_integrity_rules() -> None:
    artifact = _artifact()
    dependency = StableId.parse("ART-TWO")
    with pytest.raises(ValueError, match="type"):
        replace(artifact, type="")
    with pytest.raises(ValueError, match="fingerprint"):
        replace(artifact, fingerprint="BAD")
    with pytest.raises(ValueError, match="itself"):
        replace(artifact, depends_on=(artifact.id,))
    with pytest.raises(ValueError, match="unique"):
        replace(artifact, depends_on=(dependency, dependency))
    value = artifact.to_dict()
    assert Artifact.from_dict(value) == artifact
    value["metadata"] = []
    with pytest.raises(ValueError, match="metadata"):
        Artifact.from_dict(value)

    entity = StructuredEntity(
        StableId.parse("REQ-F-001"),
        EntityKind.REQUIREMENT,
        "Requirement",
        "The outcome must be durable.",
        artifact.id,
    )
    with pytest.raises(ValueError, match="title"):
        replace(entity, title="")
    with pytest.raises(ValueError, match="unique"):
        replace(entity, depends_on=(dependency, dependency))
    assert StructuredEntity.from_dict(entity.to_dict()) == entity
    with pytest.raises(ValueError, match="project id"):
        ProjectInfo("", "Project", "", ProjectLifecycle.GREENFIELD)

    base = ProjectModel(
        ProjectInfo("project-contract", "Project", "", ProjectLifecycle.GREENFIELD),
        GitState(False, None, None, None, None),
        (artifact,),
        (entity,),
        knowledge_adoptions=(_knowledge(),),
        research_adoptions=(_research(),),
    )
    assert ProjectModel.from_dict(base.to_dict()) == base
    for changes, message in (
        ({"schema_version": "2.0"}, "unsupported"),
        ({"artifacts": (artifact, artifact)}, "identifiers"),
        ({"artifacts": (artifact, _artifact("ART-TWO"))}, "paths"),
        ({"entities": (entity, entity)}, "entity identifiers"),
        ({"entities": (replace(entity, artifact_id=dependency),)}, "missing artifacts"),
        ({"knowledge_adoptions": (_knowledge(), _knowledge())}, "only once"),
        ({"research_adoptions": (_research(), _research())}, "only once"),
    ):
        with pytest.raises(ValueError, match=message):
            replace(base, **changes)


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        {"project": [], "git": {}},
        {"project": {}, "git": [], "artifacts": []},
        {"project": {}, "git": {}, "artifacts": "bad"},
    ],
)
def test_project_decoder_rejects_wrong_container_types(value: dict[str, object]) -> None:
    with pytest.raises((ValueError, KeyError)):
        ProjectModel.from_dict(value)
