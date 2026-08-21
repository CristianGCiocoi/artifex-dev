from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from hypothesis import given
from hypothesis import strategies as st

from artifex.ids import StableId
from artifex.project import (
    Artifact,
    ArtifactCorruptError,
    ArtifactIndex,
    ArtifactNotFoundError,
    ArtifactParser,
    ArtifactStatus,
    AuditLog,
    ChangeSet,
    ChangeSetRepository,
    ChangeSetStatus,
    EntityKind,
    FileSystemProjectStore,
    GitState,
    InvalidTransitionError,
    ProjectInfo,
    ProjectLifecycle,
    ProjectModel,
    Provenance,
    StructuredEntity,
    WorkflowDepth,
)


def _artifact(
    artifact_id: str,
    path: str,
    *,
    depends_on: tuple[str, ...] = (),
    status: ArtifactStatus = ArtifactStatus.ACCEPTED,
) -> Artifact:
    content = artifact_id.encode()
    return Artifact(
        id=StableId.parse(artifact_id),
        type="requirement",
        path=path,
        status=status,
        fingerprint=hashlib.sha256(content).hexdigest(),
        depends_on=tuple(StableId.parse(item) for item in depends_on),
        provenance=Provenance(path, "a" * 40),
    )


@pytest.mark.unit
def test_project_model_round_trip_validates_against_schema() -> None:
    artifact = _artifact("REQ-F-001", "requirements/REQ-F-001.md")
    entity = StructuredEntity(
        id=StableId.parse("REQ-F-001"),
        kind=EntityKind.REQUIREMENT,
        title="Initialize",
        statement="Initialize a greenfield project.",
        artifact_id=artifact.id,
    )
    model = ProjectModel(
        project=ProjectInfo(
            "artifex", "ARTIFEX", "Canonical model", ProjectLifecycle.GREENFIELD, WorkflowDepth.DEEP
        ),
        git=GitState(True, "main", "a" * 40, "b" * 40, False),
        artifacts=(artifact,),
        entities=(entity,),
    )

    value = model.to_dict()
    schema_path = Path(__file__).parents[1] / "schemas" / "project-model.schema.json"
    jsonschema.Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8"))).validate(
        value
    )
    assert ProjectModel.from_dict(value) == model


@pytest.mark.unit
def test_project_model_rejects_dangling_entity_artifact() -> None:
    entity = StructuredEntity(
        id=StableId.parse("INV-001"),
        kind=EntityKind.INVARIANT,
        title="Artifact first",
        statement="Outcomes are artifacts.",
        artifact_id=StableId.parse("ART-MISSING"),
    )
    with pytest.raises(ValueError, match="missing artifacts"):
        ProjectModel(
            project=ProjectInfo("p", "P", "", ProjectLifecycle.GREENFIELD),
            git=GitState(False, None, None, None, None),
            entities=(entity,),
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "content", "expected"),
    [
        (
            "requirements/REQ-F-001.md",
            (
                b"---\nid: REQ-F-001\ntype: requirement\nstatus: ACCEPTED\n"
                b"depends_on: [INV-001]\n---\n# Init\n"
            ),
            "REQ-F-001",
        ),
        ("invariants/INV-001.yaml", b"id: INV-001\ntype: invariant\n", "INV-001"),
        ("tasks/M01-T01.json", b'{"id":"M01-T01","type":"task"}', "M01-T01"),
    ],
)
def test_parser_indexes_markdown_yaml_and_json(path: str, content: bytes, expected: str) -> None:
    artifact = ArtifactParser().parse(path, content, commit="c" * 40)
    assert str(artifact.id) == expected
    assert artifact.fingerprint == hashlib.sha256(content).hexdigest()
    assert artifact.provenance == Provenance(path, "c" * 40)


@pytest.mark.unit
def test_parser_rejects_corrupt_managed_artifact() -> None:
    with pytest.raises(ArtifactCorruptError, match="unterminated"):
        ArtifactParser().parse("requirements/REQ-F-001.md", b"---\nid: REQ-F-001\n")
    with pytest.raises(ArtifactCorruptError, match="no stable id"):
        ArtifactParser().parse("notes.md", b"ordinary brownfield content")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "content", "message"),
    [
        ("artifact.txt", b"id: ART-A", "unsupported"),
        ("ART-A.json", b"\xff", "not UTF-8"),
        ("ART-A.json", b"[]", "must be an object"),
        ("ART-A.yaml", b"id: ART-A\nstatus: unknown\n", "invalid artifact status"),
        ("ART-A.yaml", b"id: ART-A\ndepends_on: ART-B\n", "depends_on must be an array"),
        ("ART-A.yaml", b"id: ART-A\nwhen: 2026-01-01\n", "not JSON-compatible"),
    ],
)
def test_parser_has_explicit_format_and_corruption_semantics(
    path: str, content: bytes, message: str
) -> None:
    with pytest.raises(ArtifactCorruptError, match=message):
        ArtifactParser().parse(path, content)


@pytest.mark.unit
def test_index_build_can_ignore_brownfield_data_or_enforce_managed_strictness(
    tmp_path: Path,
) -> None:
    store = FileSystemProjectStore(tmp_path)
    store.write_atomic("ordinary.md", b"ordinary brownfield content")
    store.write_atomic("REQ-F-001.md", b"# REQ-F-001\n")

    index = ArtifactIndex.build(store)

    assert [str(item.id) for item in index.artifacts] == ["REQ-F-001"]
    with pytest.raises(ArtifactCorruptError, match="no stable id"):
        ArtifactIndex.build(store, strict=True)
    with pytest.raises(ArtifactNotFoundError):
        store.read("absent.md")


@pytest.mark.unit
def test_dependency_staleness_is_transitive_and_cycle_safe() -> None:
    first = _artifact("ART-A", "a.md", depends_on=("ART-C",))
    second = _artifact("ART-B", "b.md", depends_on=("ART-A",))
    third = _artifact("ART-C", "c.md", depends_on=("ART-B",))
    index = ArtifactIndex((first, second, third))

    assert [str(item) for item in index.mark_stale(("ART-A",))] == ["ART-A", "ART-B", "ART-C"]
    assert all(artifact.status is ArtifactStatus.STALE for artifact in index.artifacts)


@pytest.mark.integration
def test_external_edit_reconciliation_updates_fingerprint_and_stales_dependents(
    tmp_path: Path,
) -> None:
    store = FileSystemProjectStore(tmp_path)
    store.write_atomic("a.md", b"ART-A")
    store.write_atomic("b.md", b"ART-B")
    index = ArtifactIndex(
        (
            replace(_artifact("ART-A", "a.md"), fingerprint=store.fingerprint("a.md")),
            replace(
                _artifact("ART-B", "b.md", depends_on=("ART-A",)),
                fingerprint=store.fingerprint("b.md"),
            ),
        )
    )
    store.write_atomic("a.md", b"externally edited")

    events = index.reconcile(store, observed_at=datetime(2026, 1, 2, tzinfo=UTC))

    assert len(events) == 1
    assert events[0].kind == "EXTERNAL_EDIT"
    assert events[0].observed_at == "2026-01-02T00:00:00Z"
    assert [str(item) for item in events[0].stale_artifacts] == ["ART-A", "ART-B"]
    assert index.get("ART-A").fingerprint == store.fingerprint("a.md")
    assert index.get("ART-B").status is ArtifactStatus.STALE
    assert index.reconcile(store) == ()


@pytest.mark.integration
def test_changeset_lifecycle_persistence_and_append_only_audit(tmp_path: Path) -> None:
    store = FileSystemProjectStore(tmp_path)
    repository = ChangeSetRepository(store)
    audit = AuditLog(tmp_path)
    changeset = ChangeSet(
        StableId.parse("CHG-LOGIN"),
        "Login",
        "Change the brownfield login flow.",
        (StableId.parse("REQ-F-001"),),
        baseline_commit="a" * 40,
    )
    repository.save(changeset)
    assert repository.load(changeset.id) == changeset

    for target in (
        ChangeSetStatus.ACCEPTED,
        ChangeSetStatus.IMPLEMENTING,
        ChangeSetStatus.VERIFIED,
        ChangeSetStatus.APPLIED,
        ChangeSetStatus.ARCHIVED,
    ):
        changeset = changeset.transition(
            target, actor="tester", audit_log=audit, commit="b" * 40
        )
        repository.save(changeset)

    events = audit.read_all()
    assert len(events) == 5
    assert [event.payload["to"] for event in events] == [
        "ACCEPTED",
        "IMPLEMENTING",
        "VERIFIED",
        "APPLIED",
        "ARCHIVED",
    ]
    assert all(event.commit == "b" * 40 for event in events)
    with pytest.raises(InvalidTransitionError):
        changeset.transition(ChangeSetStatus.PROPOSED, actor="tester")
    with pytest.raises(InvalidTransitionError, match="unknown"):
        changeset.transition("NOT-A-STATUS", actor="tester")


@given(st.sampled_from(list(ChangeSetStatus)), st.sampled_from(list(ChangeSetStatus)))
@pytest.mark.unit
def test_changeset_only_accepts_the_single_forward_transition(
    current: ChangeSetStatus, target: ChangeSetStatus
) -> None:
    changeset = ChangeSet(
        StableId.parse("CHG-PROPERTY"),
        "Property",
        "Lifecycle property test.",
        (),
        status=current,
    )
    allowed = {
        ChangeSetStatus.PROPOSED: ChangeSetStatus.ACCEPTED,
        ChangeSetStatus.ACCEPTED: ChangeSetStatus.IMPLEMENTING,
        ChangeSetStatus.IMPLEMENTING: ChangeSetStatus.VERIFIED,
        ChangeSetStatus.VERIFIED: ChangeSetStatus.APPLIED,
        ChangeSetStatus.APPLIED: ChangeSetStatus.ARCHIVED,
    }
    if allowed.get(current) is target:
        assert changeset.transition(target, actor="property").status is target
    else:
        with pytest.raises(InvalidTransitionError):
            changeset.transition(target, actor="property")
