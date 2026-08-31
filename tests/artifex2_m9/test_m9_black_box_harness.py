from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.artifex2.qualify_m9_black_box import (
    QualificationFailure,
    _assert_migration_validation,
    _blocked,
    _installed_identity,
)


def test_installed_identity_binds_native_manifest_and_candidate_source(tmp_path: Path) -> None:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"native-m9")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    source = "1" * 40
    manifest = {
        "install_root": str(tmp_path.resolve()),
        "artifact_manifest": {
            "artifact": "artifex.exe",
            "sha256": digest,
            "source_commit": source,
        },
        "files": [{"path": "artifex.exe", "sha256": digest}],
    }
    (tmp_path / "artifex-install-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    identity = _installed_identity(
        executable,
        expected_source_commit=source,
        forbidden_repo_root=None,
    )

    assert identity["native"] is True
    assert identity["executable_sha256"] == digest
    with pytest.raises(QualificationFailure, match="expected native candidate"):
        _installed_identity(
            executable,
            expected_source_commit="2" * 40,
            forbidden_repo_root=None,
        )


def test_black_box_validation_and_blocker_are_fail_closed_and_secret_safe() -> None:
    _assert_migration_validation(
        {
            "migration_validation": "PASS",
            "checks": {"semantic_assets": True, "runtime_history": True},
            "first_new_run": {"status": "PASS"},
        },
        first_run="PASS",
    )
    with pytest.raises(QualificationFailure, match="every check"):
        _assert_migration_validation(
            {
                "migration_validation": "FAIL",
                "checks": {"semantic_assets": False},
                "first_new_run": {"status": "FAIL"},
            },
            first_run="PASS",
        )
    blocked = _blocked("TEST", "failed approve-sensitive-value")
    assert "approve-sensitive-value" not in json.dumps(blocked)
    assert blocked["status"] == "BLOCKED"
