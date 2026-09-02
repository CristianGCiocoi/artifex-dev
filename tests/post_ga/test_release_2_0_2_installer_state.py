"""ARTIFEX 2.0.2 canonical-state and health-gated installer contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifex.distribution.doctor import run_installation_doctor
from artifex.distribution.installed_state import (
    InstalledStateRecord,
    canonical_state_root,
    discover_canonical_state_root,
    installation_record_path,
    migrate_legacy_state,
    read_installed_state_record,
    write_installed_state_record,
)
from artifex.distribution.lifecycle import MANIFEST_NAME
from artifex.distribution.service_registration import (
    SERVICE_READINESS_RECORD_NAME,
    SERVICE_REGISTRATION_MANIFEST_NAME,
    ServiceRegistrationSpec,
)

ROOT = Path(__file__).resolve().parents[2]


def _service_manifest(install_root: Path, state_root: Path):  # type: ignore[no-untyped-def]
    executable = install_root / "artifex.exe"
    return ServiceRegistrationSpec(
        service_id="artifex-managed-service",
        service_version="2.0.2",
        executable=str(executable.resolve()),
        executable_sha256="a" * 64,
        arguments=(
            "service",
            "serve",
            "--state-root",
            str(state_root.resolve()),
            "--service-id",
            "artifex-managed-service",
        ),
        working_directory=str(install_root.resolve()),
        state_root=str(state_root.resolve()),
    ).manifest()


@pytest.mark.unit
def test_installed_location_record_is_digest_bound_and_drives_default_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = tmp_path / "LocalAppData"
    install_root = tmp_path / "Program Files" / "ARTIFEX"
    state_root = canonical_state_root(local_app_data=local)
    path = installation_record_path(local_app_data=local)
    record = InstalledStateRecord(install_root.resolve(), state_root, "2.0.2")
    write_installed_state_record(record, path)

    assert read_installed_state_record(path) == record
    assert discover_canonical_state_root(record_path=path) == state_root
    monkeypatch.setenv("ARTIFEX_STATE_ROOT", str(tmp_path / "explicit-env"))
    assert discover_canonical_state_root(record_path=path) == (tmp_path / "explicit-env")
    assert discover_canonical_state_root(tmp_path / "explicit", record_path=path) == (
        tmp_path / "explicit"
    )

    value = json.loads(path.read_text(encoding="utf-8"))
    value["state_root"] = str(tmp_path / "tampered")
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.delenv("ARTIFEX_STATE_ROOT")
    with pytest.raises(ValueError, match="digest"):
        discover_canonical_state_root(record_path=path)


@pytest.mark.integration
def test_legacy_runtime_is_copied_verified_and_retained_for_rollback(tmp_path: Path) -> None:
    legacy = tmp_path / "ARTIFEX" / "runtime"
    canonical = tmp_path / "ARTIFEX" / "state"
    legacy_workspaces = legacy.with_name("runtime-workspaces")
    (legacy / "nested").mkdir(parents=True)
    (legacy / "nested" / "runstore.sqlite3").write_bytes(b"durable-state")
    legacy_workspaces.mkdir()
    (legacy_workspaces / "workspace.txt").write_text("owned", encoding="utf-8")

    first = migrate_legacy_state(source=legacy, target=canonical)
    assert first.status == "COPIED_LEGACY_STATE"
    assert first.legacy_retained is True
    assert (canonical / "nested" / "runstore.sqlite3").read_bytes() == b"durable-state"
    assert (canonical.with_name("state-workspaces") / "workspace.txt").is_file()
    assert legacy.is_dir()

    second = migrate_legacy_state(source=legacy, target=canonical)
    assert second.status == "LEGACY_COPY_ALREADY_PRESENT"
    (canonical / "nested" / "runstore.sqlite3").write_bytes(b"drift")
    with pytest.raises(ValueError, match="ambiguous"):
        migrate_legacy_state(source=legacy, target=canonical)


@pytest.mark.unit
def test_installation_doctor_binds_version_state_registration_health_and_receipt(
    tmp_path: Path,
) -> None:
    install_root = (tmp_path / "installed").resolve()
    state_root = (tmp_path / "local" / "ARTIFEX" / "state").resolve()
    record_path = state_root.parent / "installation.json"
    install_root.mkdir(parents=True)
    state_root.mkdir(parents=True)
    (install_root / "artifex.exe").write_bytes(b"shipping")
    (install_root / MANIFEST_NAME).write_text("{}", encoding="utf-8")
    record = InstalledStateRecord(install_root, state_root, "2.0.2")
    write_installed_state_record(record, record_path)
    service = _service_manifest(install_root, state_root)
    (install_root / SERVICE_REGISTRATION_MANIFEST_NAME).write_bytes(service.canonical_bytes())
    (state_root / SERVICE_READINESS_RECORD_NAME).write_text(
        json.dumps(
            {
                "status": "READY",
                "service_manifest_sha256": service.manifest_sha256,
                "persistence_checked": True,
                "semantic_health_checked": True,
            }
        ),
        encoding="utf-8",
    )

    report = run_installation_doctor(
        record_path=record_path,
        service_probe=lambda _: {"status": "PASS", "lifecycle_state": "RUNNING"},
    )
    assert report["status"] == "PASS"
    assert all(check["status"] == "PASS" for check in report["checks"])
    assert report["mutated"] is False


@pytest.mark.packaging
def test_nsis_uses_canonical_state_and_discoverable_health_gated_entrypoints() -> None:
    script = (ROOT / "packaging" / "windows" / "ARTIFEX-Setup.nsi").read_text(encoding="utf-8")
    assert "$LOCALAPPDATA\\ARTIFEX\\state" in script
    assert "$LOCALAPPDATA\\ARTIFEX\\runtime" not in script
    assert 'CreateShortcut "${ARTIFEX_START_MENU}\\ARTIFEX.lnk"' in script
    assert '"$INSTDIR\\artifex.exe" "dashboard"' in script
    assert 'CreateShortcut "${ARTIFEX_START_MENU}\\Uninstall ARTIFEX.lnk"' in script
    assert '!define MUI_FINISHPAGE_RUN_PARAMETERS "dashboard"' in script
    health_gate = script.index("_installer-lifecycle install")
    shortcut = script.index('CreateShortcut "${ARTIFEX_START_MENU}\\ARTIFEX.lnk"')
    assert health_gate < shortcut
