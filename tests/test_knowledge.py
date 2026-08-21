from __future__ import annotations

import copy
import json
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from hypothesis import given
from hypothesis import strategies as st

from artifex.ids import StableId
from artifex.knowledge import (
    CandidateOverlay,
    ImprovementProposal,
    InstanceKnowledgeStore,
    KnowledgeIsolationError,
    KnowledgeItem,
    KnowledgeKind,
    KnowledgeProvenance,
    KnowledgeScope,
    KnowledgeState,
    OverlayPrivilegeError,
    OverlayUpdateAssessment,
    OverlayValidationStatus,
    ProjectLessonStore,
    PromotionDeniedError,
    PromotionPolicy,
    RevisitKind,
    RevisitTrigger,
    Sensitivity,
    UpdateClassification,
    VerifiedAgainst,
    inspect_divergence,
    promote_knowledge,
)
from artifex.policy import PrivilegePolicy


def _provenance(*, integration: str | None = None) -> KnowledgeProvenance:
    return KnowledgeProvenance(
        source="test observation",
        observed_at="2026-08-21T00:00:00Z",
        artifact=None if integration else "tests/test_knowledge.py",
        integration=integration,
        evidence_ids=("EVD-KNOWLEDGE",),
    )


def _lesson(
    identifier: str = "LES-ISOLATION",
    *,
    scope: KnowledgeScope = KnowledgeScope.INSTANCE,
    project_id: str | None = None,
    run_id: str | None = None,
    integration: str | None = None,
    confidence: float = 0.9,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
) -> KnowledgeItem:
    return KnowledgeItem(
        id=StableId.parse(identifier),
        scope=scope,
        kind=KnowledgeKind.LESSON,
        statement=f"Lesson {identifier} remains explicitly scoped.",
        provenance=(_provenance(integration=integration),),
        confidence=confidence,
        sensitivity=sensitivity,
        promotion_policy=PromotionPolicy(),
        verified_against=(
            VerifiedAgainst("docs/architecture/INVARIANTS.md", "a" * 64, "2026-08-21T00:00:00Z"),
        ),
        revisit_triggers=(RevisitTrigger(RevisitKind.ARTIFACT_CHANGED, "INV-021"),),
        project_id=project_id,
        run_id=run_id,
    )


def _proposal() -> ImprovementProposal:
    return ImprovementProposal(
        id=StableId.parse("IMP-KNOWLEDGE"),
        title="Improve knowledge lookup",
        lesson_ids=(StableId.parse("LES-ISOLATION"),),
        target="knowledge lookup workflow",
        reason="Repeated isolated observations support the change.",
        expected_benefit="Fewer irrelevant records.",
        evidence=("EVD-ONE", "EVD-TWO"),
        requested_privileges=frozenset({"repository_read"}),
    )


def _overlay(
    identifier: str = "overlay-knowledge",
    *,
    privileges: frozenset[str] = frozenset({"repository_read"}),
    status: OverlayValidationStatus = OverlayValidationStatus.PASSED,
) -> CandidateOverlay:
    return CandidateOverlay(
        id=identifier,
        proposal_id=StableId.parse("IMP-KNOWLEDGE"),
        origin_core_version="1.0.0",
        reason="Apply a validated local lookup preference.",
        evidence=("EVD-ONE",),
        target="knowledge.lookup",
        expected_benefit="More precise lookup.",
        compatibility="Compatible with Core 1.x.",
        validation_status=status,
        changes={"knowledge": {"lookup_limit": 8}},
        requested_privileges=privileges,
    )


@pytest.mark.unit
def test_project_lesson_round_trip_and_schema() -> None:
    lesson = _lesson(scope=KnowledgeScope.PROJECT, project_id="artifex")
    value = lesson.to_dict()
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "knowledge.schema.json").read_text("utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(value)
    assert KnowledgeItem.from_dict(value) == lesson


@pytest.mark.unit
def test_provenance_confidence_sensitivity_and_secret_boundaries() -> None:
    with pytest.raises(ValueError, match="confidence"):
        replace(_lesson(), confidence=1.01)
    with pytest.raises(ValueError, match="secret-like"):
        replace(_lesson(), statement="token=super-secret")
    with pytest.raises(ValueError, match="provenance"):
        replace(_lesson(), provenance=())


@pytest.mark.unit
def test_revisit_trigger_marks_knowledge_stale_without_mutating_original() -> None:
    lesson = _lesson()
    current = lesson.revisit(changed_artifacts=frozenset({"OTHER"}))
    stale = lesson.revisit(changed_artifacts=frozenset({"INV-021"}))
    assert current is lesson
    assert stale.state is KnowledgeState.STALE
    assert lesson.state is KnowledgeState.CURRENT


@pytest.mark.unit
def test_time_and_core_revisit_triggers_are_mechanical() -> None:
    lesson = replace(
        _lesson(),
        revisit_triggers=(
            RevisitTrigger(RevisitKind.CORE_VERSION_CHANGED, "1.0.0"),
            RevisitTrigger(RevisitKind.DATE_REACHED, "2026-09-01T00:00:00Z"),
        ),
    )
    assert lesson.revisit(current_core_version="1.1.0").state is KnowledgeState.STALE
    assert (
        lesson.revisit(current_core_version="1.0.0", now=datetime(2026, 9, 2, tzinfo=UTC)).state
        is KnowledgeState.STALE
    )


@pytest.mark.unit
def test_promotion_is_adjacent_evidence_bound_and_stops_at_instance() -> None:
    run = _lesson(scope=KnowledgeScope.RUN, run_id="run-1")
    project = promote_knowledge(
        run,
        KnowledgeScope.PROJECT,
        evidence=("EVD-ONE",),
        independently_validated=True,
        project_id="artifex",
    )
    assert project.scope is KnowledgeScope.PROJECT
    with pytest.raises(PromotionDeniedError, match="at least 2"):
        promote_knowledge(
            project,
            KnowledgeScope.INSTANCE,
            evidence=("EVD-ONE",),
            independently_validated=True,
        )
    instance = promote_knowledge(
        project,
        KnowledgeScope.INSTANCE,
        evidence=("EVD-ONE", "EVD-TWO"),
        independently_validated=True,
    )
    assert instance.promoted_from is KnowledgeScope.PROJECT
    with pytest.raises(PromotionDeniedError):
        promote_knowledge(
            instance,
            KnowledgeScope.PROFILE,
            evidence=("EVD-ONE", "EVD-TWO", "EVD-THREE"),
            independently_validated=True,
        )


@given(
    confidence=st.floats(min_value=0, max_value=1, allow_nan=False),
    independently_validated=st.booleans(),
)
@pytest.mark.unit
def test_promotion_property_never_bypasses_confidence_or_validation(
    confidence: float, independently_validated: bool
) -> None:
    item = _lesson(
        scope=KnowledgeScope.RUN,
        run_id="property-run",
        confidence=confidence,
    )
    should_pass = confidence >= 0.7 and independently_validated
    if should_pass:
        promoted = promote_knowledge(
            item,
            KnowledgeScope.PROJECT,
            evidence=("EVD-ONE",),
            independently_validated=independently_validated,
            project_id="artifex",
        )
        assert promoted.scope is KnowledgeScope.PROJECT
    else:
        with pytest.raises(PromotionDeniedError):
            promote_knowledge(
                item,
                KnowledgeScope.PROJECT,
                evidence=("EVD-ONE",),
                independently_validated=independently_validated,
                project_id="artifex",
            )


@pytest.mark.integration
def test_two_instances_diverge_without_core_mutation_or_contamination(tmp_path: Path) -> None:
    core = tmp_path / "installed-core"
    core.mkdir()
    core_file = core / "defaults.json"
    core_file.write_text('{"knowledge":{"lookup_limit":4}}', encoding="utf-8")
    state = tmp_path / "state"
    alpha = InstanceKnowledgeStore(state, "alpha", core_root=core)
    beta = InstanceKnowledgeStore(state, "beta", core_root=core)

    alpha.add(_lesson("LES-ALPHA"))
    beta.add(_lesson("LES-BETA"))
    alpha.add_proposal(_proposal())
    alpha.add_overlay(_overlay())

    assert [str(item.id) for item in alpha.list()] == ["LES-ALPHA"]
    assert [str(item.id) for item in beta.list()] == ["LES-BETA"]
    assert beta.list_proposals() == ()
    assert beta.list_overlays() == ()
    assert alpha.root != beta.root
    assert core_file.read_text("utf-8") == '{"knowledge":{"lookup_limit":4}}'


@pytest.mark.integration
def test_project_and_instance_filesystem_stores_reject_cross_scope(tmp_path: Path) -> None:
    project = ProjectLessonStore(tmp_path / "project", "artifex")
    instance = InstanceKnowledgeStore(tmp_path / "state", "local")
    project_lesson = _lesson(scope=KnowledgeScope.PROJECT, project_id="artifex")
    project.add(project_lesson)
    instance.add(_lesson())
    with pytest.raises(KnowledgeIsolationError):
        project.add(_lesson())
    with pytest.raises(KnowledgeIsolationError):
        instance.add(project_lesson)
    assert project.root != instance.root


@given(st.text(min_size=0, max_size=40))
@pytest.mark.unit
def test_instance_namespace_property_cannot_escape_state_root(value: str) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        try:
            store = InstanceKnowledgeStore(root, value)
        except KnowledgeIsolationError:
            return
        assert store.root.is_relative_to((root / "instances").resolve())
        assert store.root.parent == (root / "instances").resolve()


@pytest.mark.parametrize("value", ["NUL", "nul.txt", "CON", "COM1.log", "name."])
def test_instance_namespace_rejects_nonportable_windows_names(
    tmp_path: Path, value: str
) -> None:
    with pytest.raises(KnowledgeIsolationError):
        InstanceKnowledgeStore(tmp_path, value)


@pytest.mark.integration
@pytest.mark.parametrize("provider", ["hermes", "codex", "claude"])
def test_integration_memory_is_auxiliary_and_provider_isolated(
    provider: str, tmp_path: Path
) -> None:
    store = InstanceKnowledgeStore(tmp_path, "local")
    lesson = _lesson(f"LES-{provider.upper()}", scope=KnowledgeScope.HARNESS, integration=provider)
    store.add_integration_memory(provider, lesson)
    assert store.list_integration_memory(provider) == (lesson,)
    for other in {"hermes", "codex", "claude"} - {provider}:
        assert store.list_integration_memory(other) == ()
    with pytest.raises(KnowledgeIsolationError):
        store.add_integration_memory("other", lesson)


@pytest.mark.unit
def test_improvement_proposal_and_overlay_validate_against_schemas() -> None:
    schemas = Path(__file__).parents[1] / "schemas"
    knowledge_schema = json.loads((schemas / "knowledge.schema.json").read_text("utf-8"))
    overlay_schema = json.loads((schemas / "overlay.schema.json").read_text("utf-8"))
    jsonschema.Draft202012Validator(knowledge_schema).validate(_proposal().to_dict())
    jsonschema.Draft202012Validator(overlay_schema).validate(_overlay().to_dict())
    assert ImprovementProposal.from_dict(_proposal().to_dict()) == _proposal()
    assert CandidateOverlay.from_dict(_overlay().to_dict()) == _overlay()


@pytest.mark.unit
def test_divergence_preview_is_effective_inspectable_and_core_immutable() -> None:
    core = {"knowledge": {"lookup_limit": 4}, "security": {"sandbox": "strict"}}
    original = copy.deepcopy(core)
    report = inspect_divergence(
        core,
        (_overlay(),),
        privilege_policy=PrivilegePolicy(frozenset({"repository_read"})),
    )
    assert report.effective_configuration["knowledge"] == {"lookup_limit": 8}
    assert report.changed_paths == ("knowledge.lookup_limit",)
    assert report.core_unchanged
    assert core == original


@pytest.mark.unit
def test_privilege_ceiling_fails_closed_and_rejects_expansion() -> None:
    with pytest.raises(OverlayPrivilegeError, match="fail closed"):
        inspect_divergence({}, (_overlay(),), privilege_policy=None)
    expanded = _overlay(privileges=frozenset({"repository_read", "repository_write"}))
    with pytest.raises(OverlayPrivilegeError, match="expands privileges"):
        inspect_divergence(
            {},
            (expanded,),
            privilege_policy=PrivilegePolicy(frozenset({"repository_read"})),
        )
    with pytest.raises(ValueError, match="not validated"):
        inspect_divergence(
            {},
            (_overlay(status=OverlayValidationStatus.PROPOSED),),
            privilege_policy=PrivilegePolicy(frozenset({"repository_read"})),
        )


@pytest.mark.unit
@pytest.mark.parametrize("classification", list(UpdateClassification))
def test_future_update_classification_is_explicit_and_schema_valid(
    classification: UpdateClassification,
) -> None:
    assessment = OverlayUpdateAssessment(
        overlay_id="overlay-knowledge",
        from_core_version="1.0.0",
        to_core_version="1.1.0",
        classification=classification,
        reason="Explicit compatibility review result.",
    )
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "knowledge.schema.json").read_text("utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(assessment.to_dict())
    assert assessment.to_dict()["classification"] == classification.value
