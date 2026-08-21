from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from artifex.project import (
    ArtifactCorruptError,
    ArtifactIndex,
    ArtifactNotFoundError,
    AuditEvent,
    AuditLog,
    DirtyStatePolicy,
    FileSystemProjectStore,
    GitCommandError,
    GitRepository,
    ProjectLifecycle,
    ProjectRepository,
    UnsafePathError,
    normalize_relative_path,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "../secret",
        "safe/../secret",
        "/absolute",
        "C:\\Windows\\secret",
        "c:/windows/secret",
        "\\\\server\\share\\secret",
        "safe//file",
        "safe/./file",
        "nul\x00file",
        "NUL.txt",
        "folder/COM1",
        "trailing. ",
        "not:portable",
    ],
)
def test_cross_platform_unsafe_paths_are_rejected(path: str) -> None:
    with pytest.raises(UnsafePathError):
        normalize_relative_path(path)


_SAFE_SEGMENT = st.text(
    alphabet=st.characters(
        blacklist_characters="/\\\x00:<>\"|?*",
        blacklist_categories=("Cs", "Cc"),
    ),
    min_size=1,
    max_size=20,
).filter(
    lambda value: value not in {".", ".."}
    and value == value.strip(" .")
    and value.split(".", 1)[0].upper()
    not in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)


@given(st.lists(_SAFE_SEGMENT, min_size=1, max_size=5))
@pytest.mark.unit
def test_path_normalization_property_is_host_independent(parts: list[str]) -> None:
    posix = "/".join(parts)
    windows = "\\".join(parts)
    assert normalize_relative_path(posix) == posix
    assert normalize_relative_path(windows) == posix


@pytest.mark.unit
def test_store_atomic_replace_missing_and_deterministic_iteration(tmp_path: Path) -> None:
    store = FileSystemProjectStore(tmp_path)
    store.write_atomic("nested/a.txt", b"first")
    store.write_atomic("nested/a.txt", b"second")
    store.write_atomic("b.txt", b"b")

    assert store.read("nested\\a.txt") == b"second"
    assert store.fingerprint("nested/a.txt") == hashlib.sha256(b"second").hexdigest()
    assert tuple(store.iter_files()) == ("b.txt", "nested/a.txt")
    assert not list((tmp_path / "nested").glob("*.tmp"))
    with pytest.raises(ArtifactNotFoundError):
        store.read("missing.txt")


@pytest.mark.integration
def test_git_detection_dirty_state_remote_sanitization_and_baseline(tmp_path: Path) -> None:
    git = GitRepository(tmp_path)
    assert not git.inspect().initialized
    git.initialize()
    assert git.inspect().branch == "main"
    (tmp_path / "tracked.txt").write_text("baseline", encoding="utf-8")
    _git(tmp_path, "add", "tracked.txt")
    _git(
        tmp_path,
        "-c",
        "user.name=ARTIFEX Test",
        "-c",
        "user.email=artifex@example.invalid",
        "commit",
        "-m",
        "baseline",
    )
    head = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    _git(tmp_path, "remote", "add", "origin", "https://token:secret@example.com/repo.git")

    state = git.inspect(baseline_commit=head)

    assert state.current_commit == state.baseline_commit == head
    assert state.dirty is False
    assert state.remote_status == "CONFIGURED"
    assert state.remotes[0].url == "https://example.com/repo.git"
    (tmp_path / "tracked.txt").write_text("changed", encoding="utf-8")
    assert git.inspect().dirty is True
    git.inspect().enforce(DirtyStatePolicy.ALLOW)
    with pytest.raises(GitCommandError, match="clean"):
        git.inspect().enforce(DirtyStatePolicy.REQUIRE_CLEAN)


@pytest.mark.integration
def test_greenfield_init_and_brownfield_adoption_preserve_content(tmp_path: Path) -> None:
    greenfield_root = tmp_path / "green"
    green = ProjectRepository.initialize(greenfield_root, project_id="green", name="Green")
    assert green.load().project.lifecycle is ProjectLifecycle.GREENFIELD
    assert green.git.inspect().initialized

    brownfield_root = tmp_path / "brown"
    brownfield_root.mkdir()
    source = brownfield_root / "keep.txt"
    source.write_bytes(b"must survive")
    brown = ProjectRepository.adopt(brownfield_root, project_id="brown", name="Brown")

    assert source.read_bytes() == b"must survive"
    assert brown.load().project.lifecycle is ProjectLifecycle.BROWNFIELD
    assert brown.git.inspect().branch == "main"
    assert [event.event_type for event in brown.audit.read_all()] == ["PROJECT_ADOPTED"]

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="empty"):
        ProjectRepository.adopt(empty, project_id="empty", name="Empty")
    assert list(empty.iterdir()) == []


@pytest.mark.integration
def test_establish_baseline_binds_model_and_audit_to_git_commit(tmp_path: Path) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="p", name="P")
    _git(tmp_path, "add", ".artifex/project-model.json", ".artifex/audit.jsonl")
    _git(
        tmp_path,
        "-c",
        "user.name=ARTIFEX Test",
        "-c",
        "user.email=artifex@example.invalid",
        "commit",
        "-m",
        "initial",
    )
    head = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()

    model = repository.establish_baseline()

    assert model.git.baseline_commit == head
    assert repository.audit.read_all()[-1].commit == head


@pytest.mark.integration
def test_repository_reconciliation_is_recorded_in_audit(tmp_path: Path) -> None:
    repository = ProjectRepository.initialize(tmp_path, project_id="p", name="P")
    repository.store.write_atomic("ART-A.md", b"# ART-A\n")
    index = ArtifactIndex.build(repository.store)
    repository.store.write_atomic("ART-A.md", b"# ART-A\nexternal edit\n")

    events = repository.reconcile(index)

    assert len(events) == 1
    assert repository.audit.read_all()[-1].event_type == "EXTERNAL_EDIT"
    assert repository.audit.read_all()[-1].payload["artifact_id"] == "ART-A"


@pytest.mark.unit
def test_audit_refuses_to_extend_corrupt_or_truncated_history(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)
    log.append(
        AuditEvent(
            event_type="TEST",
            actor="tester",
            occurred_at="2026-01-01T00:00:00Z",
            event_id="event-1",
        )
    )
    target = tmp_path / ".artifex" / "audit.jsonl"
    before = target.read_bytes()
    target.write_bytes(before + b'{"truncated":true}')
    with pytest.raises(ArtifactCorruptError, match="truncated"):
        log.append(AuditEvent(event_type="SECOND", actor="tester"))
    assert target.read_bytes() == before + b'{"truncated":true}'


@pytest.mark.unit
def test_corrupt_project_model_has_explicit_semantics(tmp_path: Path) -> None:
    store = FileSystemProjectStore(tmp_path)
    store.write_atomic(".artifex/project-model.json", json.dumps({"bad": True}).encode())
    repository = ProjectRepository(tmp_path)
    with pytest.raises(ArtifactCorruptError, match="Project Model"):
        repository.load()


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
