from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from artifex.application import Application, OperationRequest
from artifex.ids import StableId
from artifex.knowledge import (
    InstanceKnowledgeStore,
    KnowledgeApplicability,
    KnowledgeItem,
    KnowledgeKind,
    KnowledgeProvenance,
    KnowledgeScope,
    OrganizationalKnowledgeError,
    OrganizationalKnowledgeService,
    ProjectLessonStore,
    PromotionPolicy,
    Sensitivity,
)
from artifex.project import ExternalMutationError, ProjectAuthority, ProjectRepository
from artifex.runtime import ActorPrincipal, ActorType


def _actor(*permissions: str, actor_type: ActorType = ActorType.USER) -> ActorPrincipal:
    return ActorPrincipal("knowledge-user", actor_type, True, "test", tuple(permissions))


def _project(root: Path, identifier: str) -> ProjectAuthority:
    repository = ProjectRepository.initialize(root, project_id=identifier, name=identifier)
    return ProjectAuthority.bootstrap(
        repository, actor="bootstrap", accepted_at="2026-08-27T00:00:00Z"
    )


def _lesson(
    root: Path,
    project_id: str,
    *,
    confidence: float = 0.93,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    identifier: str = "LES-J12",
) -> KnowledgeItem:
    lesson = KnowledgeItem(
        id=StableId.parse(identifier),
        scope=KnowledgeScope.PROJECT,
        kind=KnowledgeKind.LESSON,
        statement="Pin dependency versions after validating the release candidate.",
        provenance=(KnowledgeProvenance(
            source=f"project:{project_id}",
            observed_at="2026-08-27T00:01:00Z",
            artifact="evidence/release.json",
            commit="a" * 40,
            integration="manual",
            evidence_ids=("EVD-J12",),
        ),),
        confidence=confidence,
        sensitivity=sensitivity,
        promotion_policy=PromotionPolicy(),
        project_id=project_id,
    )
    ProjectLessonStore(root, project_id).add(lesson)
    return lesson


def _promote(
    service: OrganizationalKnowledgeService, root: Path, project_id: str,
    *, lesson_id: str = "LES-J12", fresh_until: str = "2027-08-27T00:00:00Z",
):
    return service.promote(
        source_project_root=root,
        source_project_id=project_id,
        lesson_id=lesson_id,
        applicability=KnowledgeApplicability(project_ids=("project-b",)),
        fresh_until=fresh_until,
        evidence_digests=("b" * 64,),
        validator_id="validator-independent",
        actor=_actor("knowledge:promote"),
        created_at="2026-08-27T00:02:00Z",
    )


@pytest.mark.integration
def test_j12_advisory_restart_then_explicit_project_authority_adoption(tmp_path: Path) -> None:
    source_root, target_root = tmp_path / "a", tmp_path / "b"
    _project(source_root, "project-a")
    target_authority = _project(target_root, "project-b")
    _lesson(source_root, "project-a")
    database = tmp_path / "organization" / "knowledge.sqlite3"
    service = OrganizationalKnowledgeService(database)
    record = _promote(service, source_root, "project-a")

    before = target_authority.current()
    model_path = target_root / ".artifex" / "project-model.json"
    before_bytes = model_path.read_bytes()
    recommendation = service.recommend(
        knowledge_id=record.id,
        target_project_root=target_root,
        target_project_id="project-b",
        actor=_actor("knowledge:recommend"),
        now="2026-08-27T00:03:00Z",
    )
    assert recommendation.advisory is True
    assert model_path.read_bytes() == before_bytes
    assert target_authority.current().number == before.number
    assert target_authority.current().fingerprint == before.fingerprint

    restarted = OrganizationalKnowledgeService(database)
    result = restarted.adopt(
        recommendation_id=recommendation.id,
        target_project_root=target_root,
        expected_revision=before.number,
        actor=_actor("knowledge:adopt"),
        accepted_at="2026-08-27T00:04:00Z",
    )
    after = ProjectAuthority(target_root).current()
    assert result["proposal"]["source"] == "ORGANIZATIONAL_KNOWLEDGE_ADOPTION"
    assert after.number == before.number + 1
    assert after.parent_fingerprint == before.fingerprint
    assert (
        after.model.knowledge_adoptions[0].source_project_fingerprint
        == record.source_project_fingerprint
    )
    assert after.model.knowledge_adoptions[0].evidence_digests == ("b" * 64,)
    assert ProjectAuthority(target_root).current() == after


@pytest.mark.adversarial
def test_low_confidence_stale_restricted_and_cross_project_records_fail_closed(
    tmp_path: Path,
) -> None:
    source_root, target_root = tmp_path / "a", tmp_path / "b"
    _project(source_root, "project-a")
    _project(target_root, "project-b")
    service = OrganizationalKnowledgeService(tmp_path / "org.sqlite3")
    _lesson(source_root, "project-a", confidence=0.6, identifier="LES-LOW")
    with pytest.raises(OrganizationalKnowledgeError, match="confidence"):
        _promote(service, source_root, "project-a", lesson_id="LES-LOW")

    _lesson(source_root, "project-a", sensitivity=Sensitivity.RESTRICTED,
            identifier="LES-SECRET")
    with pytest.raises(OrganizationalKnowledgeError, match="RESTRICTED"):
        _promote(service, source_root, "project-a", lesson_id="LES-SECRET")

    _lesson(source_root, "project-a")
    stale = _promote(
        service, source_root, "project-a", fresh_until="2026-08-27T00:02:01Z"
    )
    assert service.search(
        query="dependency", target_project_id="project-b",
        actor=_actor("knowledge:read"), now="2026-08-27T00:03:00Z"
    ) == ()
    with pytest.raises(OrganizationalKnowledgeError, match="stale"):
        service.recommend(
            knowledge_id=stale.id, target_project_root=target_root,
            target_project_id="project-b", actor=_actor("knowledge:recommend"),
            now="2026-08-27T00:03:00Z",
        )
    assert service.search(
        query="dependency", target_project_id="project-c",
        actor=_actor("knowledge:read"), now="2026-08-27T00:02:00Z"
    ) == ()


@pytest.mark.adversarial
def test_provider_tampering_and_dangling_sources_are_rejected(tmp_path: Path) -> None:
    source_root = tmp_path / "a"
    _project(source_root, "project-a")
    _lesson(source_root, "project-a")
    database = tmp_path / "org.sqlite3"
    service = OrganizationalKnowledgeService(database)
    contaminated = OrganizationalKnowledgeService(source_root / ".artifex" / "org.sqlite3")
    with pytest.raises(OrganizationalKnowledgeError, match="outside every Project"):
        contaminated.record_project_lesson(
            project_root=source_root, project_id="project-a",
            lesson=ProjectLessonStore(source_root, "project-a").list()[0],
            actor=_actor("knowledge:record"),
        )
    with pytest.raises(PermissionError, match="PROVIDER"):
        service.promote(
            source_project_root=source_root, source_project_id="project-a",
            lesson_id="LES-J12", applicability=KnowledgeApplicability(project_ids=("project-b",)),
            fresh_until="2027-08-27T00:00:00Z", evidence_digests=("b" * 64,),
            validator_id="validator", actor=_actor("*", actor_type=ActorType.PROVIDER),
        )
    with pytest.raises(OrganizationalKnowledgeError, match="missing"):
        _promote(service, source_root, "project-a", lesson_id="LES-DANGLING")

    record = _promote(service, source_root, "project-a")
    with sqlite3.connect(database) as connection:
        payload = json.loads(connection.execute(
            "SELECT payload FROM organizational_knowledge WHERE id=?", (record.id,)
        ).fetchone()[0])
        payload["statement"] = "forged cross-project content"
        connection.execute("UPDATE organizational_knowledge SET payload=? WHERE id=?",
                           (json.dumps(payload), record.id))
    with pytest.raises(OrganizationalKnowledgeError, match="tampered"):
        service.store.get_record(record.id)


@pytest.mark.adversarial
def test_recommendation_cas_and_direct_mutation_do_not_bypass_authority(tmp_path: Path) -> None:
    source_root, target_root = tmp_path / "a", tmp_path / "b"
    _project(source_root, "project-a")
    target = _project(target_root, "project-b")
    _lesson(source_root, "project-a")
    service = OrganizationalKnowledgeService(tmp_path / "org.sqlite3")
    record = _promote(service, source_root, "project-a")
    recommendation = service.recommend(
        knowledge_id=record.id, target_project_root=target_root,
        target_project_id="project-b", actor=_actor("knowledge:recommend"),
        now="2026-08-27T00:03:00Z",
    )
    repository = target.repository
    repository.save(replace(target.current().model,
                            project=replace(target.current().model.project,
                                            description="direct mutation")))
    with pytest.raises(ExternalMutationError):
        service.adopt(
            recommendation_id=recommendation.id, target_project_root=target_root,
            expected_revision=1, actor=_actor("knowledge:adopt"),
            accepted_at="2026-08-27T00:04:00Z",
        )
    assert target.current().number == 1


@pytest.mark.integration
def test_v1_migration_is_classification_quarantine_only(tmp_path: Path) -> None:
    item = KnowledgeItem(
        id=StableId.parse("LES-MIGRATION"), scope=KnowledgeScope.INSTANCE,
        kind=KnowledgeKind.LESSON, statement="A provenance-bound V1 lesson.",
        provenance=(KnowledgeProvenance(
            source="project:project-a", observed_at="2026-08-27T00:00:00Z",
            artifact="evidence/migration.json", evidence_ids=("EVD-MIGRATION",),
        ),), confidence=0.9, sensitivity=Sensitivity.INTERNAL,
        promotion_policy=PromotionPolicy(), promoted_from=KnowledgeScope.PROJECT,
    )
    state_root = tmp_path / "v1"
    InstanceKnowledgeStore(state_root, "instance-a").add(item)
    service = OrganizationalKnowledgeService(tmp_path / "org.sqlite3")
    values = service.classify_v1_instance(
        state_root=state_root, instance_id="instance-a",
        actor=_actor("knowledge:migrate"), apply=True,
    )
    assert values[0]["classification"] == "ELIGIBLE_QUARANTINE"
    assert values[0]["acceptance"] == "N/A"
    assert values[0]["searchable"] is False
    assert service.store.records() == ()


@pytest.mark.integration
def test_public_application_exposes_m8a_operations(tmp_path: Path) -> None:
    names = Application().dispatch(OperationRequest("system.operations")).value["operations"]
    assert "knowledge.organizational.promote" in names
    assert "knowledge.organizational.search" in names
    assert "knowledge.organizational.recommend" in names
    assert "knowledge.project.adopt" in names
