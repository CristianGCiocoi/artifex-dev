from __future__ import annotations

import json
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

import artifex.capabilities.interaction as interaction
import artifex.distribution.lifecycle as lifecycle
import artifex.distribution.service_registration as registration
from artifex.distribution.service_registration import (
    ServiceRegistrationDriftError,
    ServiceRegistrationManifest,
    ServiceRegistrationObservation,
    UnsupportedServicePlatformError,
    UnsupportedServiceRegistrationAdapter,
)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (("codex",), ("codex",)),
        (("codex.exe",), ("codex.exe",)),
        (("codex.cmd",), ("codex.cmd",)),
        (
            ("npx", "--yes", "@openai/codex@1.2.3"),
            ("npx", "--yes", "@openai/codex@1.2.3"),
        ),
    ],
)
def test_codex_command_boundary_accepts_only_exact_supported_prefixes(
    command: tuple[str, ...], expected: tuple[str, ...]
) -> None:
    assert interaction._validated_codex_prefix(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        (),
        ("",),
        ("codex", "exec"),
        ("python",),
        ("npx", "@openai/codex@1.2.3"),
        ("npx", "--yes", "@openai/codex@latest"),
        ("npx", "--yes", "@openai/codex@1.2.3", "exec"),
        ("codex\0",),
    ],
)
def test_codex_command_boundary_rejects_flags_unpinned_packages_and_nul(
    command: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError):
        interaction._validated_codex_prefix(command)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (("claude",), ("claude",)),
        (("claude.exe",), ("claude.exe",)),
        (("claude.cmd",), ("claude.cmd",)),
        (
            ("npx", "--yes", "@anthropic-ai/claude-code@1.2.3"),
            ("npx", "--yes", "@anthropic-ai/claude-code@1.2.3"),
        ),
    ],
)
def test_claude_command_boundary_accepts_only_exact_supported_prefixes(
    command: tuple[str, ...], expected: tuple[str, ...]
) -> None:
    assert interaction._validated_claude_prefix(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        (),
        ("",),
        ("claude", "--print"),
        ("python",),
        ("npx", "@anthropic-ai/claude-code@1.2.3"),
        ("npx", "--yes", "@anthropic-ai/claude-code@latest"),
        ("npx", "--yes", "@anthropic-ai/claude-code@1.2.3", "--print"),
        ("claude\0",),
    ],
)
def test_claude_command_boundary_rejects_flags_unpinned_packages_and_nul(
    command: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError):
        interaction._validated_claude_prefix(command)


def _codex_event(event_type: str, **values: Any) -> str:
    return json.dumps({"type": event_type, **values})


def test_codex_and_claude_final_response_parsers_accept_exact_terminal_shapes() -> None:
    output = "\n".join(
        (
            _codex_event("thread.started"),
            _codex_event("turn.started"),
            _codex_event("item.completed", item={"type": "agent_message", "text": "progress"}),
            _codex_event("item.completed", item={"type": "agent_message", "text": "final"}),
            _codex_event("turn.completed"),
        )
    )
    assert interaction._final_agent_response(output) == "final"
    assert (
        interaction._final_claude_response(
            json.dumps({"is_error": False, "structured_output": {"response": "answer"}})
        )
        == "answer"
    )
    schema = json.loads(interaction._claude_interaction_schema())
    assert schema["properties"]["response"]["maxLength"] > 0
    prompt = interaction._claude_transport_prompt('answer "safely"')
    assert 'USER_REQUEST_JSON="answer \\"safely\\""' in prompt


@pytest.mark.parametrize(
    "output",
    [
        "",
        "\n",
        "not-json",
        "[]",
        _codex_event("error"),
        _codex_event("turn.failed"),
        "\n".join((_codex_event("turn.completed"), _codex_event("thread.started"))),
        "\n".join(
            (
                _codex_event("thread.started"),
                _codex_event("turn.started"),
                _codex_event("item.completed", item={"type": "agent_message", "text": " "}),
                _codex_event("turn.completed"),
            )
        ),
        "\n".join(
            (
                _codex_event("thread.started"),
                _codex_event("turn.started"),
                _codex_event("item.completed", item={"type": "tool", "text": "ignored"}),
                _codex_event("turn.completed"),
            )
        ),
        '{"type":"thread.started","type":"turn.started"}',
    ],
)
def test_codex_final_response_parser_rejects_ambiguous_or_incomplete_streams(
    output: str,
) -> None:
    with pytest.raises(ValueError):
        interaction._final_agent_response(output)


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        "[]",
        json.dumps({"is_error": True, "structured_output": {"response": "answer"}}),
        json.dumps({"is_error": False}),
        json.dumps({"is_error": False, "structured_output": {"response": "", "extra": 1}}),
        json.dumps({"is_error": False, "structured_output": {"response": " "}}),
        '{"structured_output":{"response":"a","response":"b"}}',
    ],
)
def test_claude_final_response_parser_rejects_ambiguous_or_failed_payloads(output: str) -> None:
    with pytest.raises(ValueError):
        interaction._final_claude_response(output)


def test_provider_response_sanitization_scrubs_controls_secrets_and_bounds_output() -> None:
    value, truncated = interaction._sanitize_response(
        "\x1b[31manswer\x1b[0m\x00 api_key=secret-value "
        "Authorization: Bearer token-value-long"
    )
    assert truncated is False
    assert "\x1b" not in value and "\x00" not in value
    assert "secret-value" not in value and "token-value-long" not in value
    clipped, truncated = interaction._sanitize_response("x" * 200_000)
    assert truncated is True
    assert clipped.endswith("[OUTPUT TRUNCATED]")
    with pytest.raises(json.JSONDecodeError):
        interaction._unique_object([("duplicate", 1), ("duplicate", 2)])
    assert len(interaction._sha256_text("value")) == 64
    assert len(interaction._sha256_json({"value": 1})) == 64


def test_interaction_git_baseline_supports_committed_and_unborn_projects(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    assert interaction._git_head(repository).startswith("UNBORN:")
    with pytest.raises(ValueError, match="inspection failed"):
        interaction._git(repository, "rev-parse", "--verify", "missing")

    subprocess.run(["git", "-C", str(repository), "config", "user.name", "CI"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "ci@example.invalid"],
        check=True,
    )
    (repository / ".artifex").mkdir()
    (repository / ".artifex" / "project-model.json").write_text("{}", encoding="utf-8")
    (repository / ".artifex" / "integrations.json").write_text("{}", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "baseline"], check=True)
    baseline = interaction._capture_baseline(repository.resolve())
    assert len(baseline.git_head) == 40
    assert all(
        len(value) == 64
        for value in baseline.to_dict().values()
        if value != baseline.git_head
    )
    with pytest.raises(ValueError, match="exact Git worktree root"):
        interaction._capture_baseline((repository / ".artifex").resolve())


@pytest.mark.parametrize(
    "manifest",
    [
        {},
        {"files": "not-list"},
        {"files": []},
        {"files": [1]},
        {"files": [{"path": "file", "kind": "unknown", "sha256": "0" * 64}]},
        {"files": [{"path": "file", "kind": "file", "sha256": "invalid"}]},
        {
            "files": [
                {"path": "link", "kind": "symlink", "target": "", "sha256": "0" * 64}
            ]
        },
    ],
)
def test_install_manifest_entry_parser_rejects_ambiguous_authority(
    manifest: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        lifecycle._manifest_entries(manifest, "files", required=True)


def test_lifecycle_path_signature_key_and_process_helpers_are_fail_closed(tmp_path: Path) -> None:
    root = (tmp_path / "install").resolve()
    root.mkdir()
    child = lifecycle._safe_child(root, "folder/file")
    assert child == root / "folder" / "file"
    for unsafe in ("", ".", "..", "../escape", "/absolute", "C:/absolute"):
        with pytest.raises(ValueError):
            lifecycle._safe_child(root, unsafe)

    key_path = tmp_path / "security" / "key"
    key = lifecycle._create_install_key(key_path)
    assert len(key) >= 32
    assert lifecycle._load_install_key(key_path) == key
    with pytest.raises(FileExistsError):
        lifecycle._create_install_key(key_path)
    key_path.write_bytes(b"short")
    with pytest.raises(ValueError):
        lifecycle._load_install_key(key_path)

    signed = lifecycle._signed_value({"value": 1}, b"k" * 32)
    assert lifecycle._verify_signed_value(signed, b"k" * 32) is True
    assert lifecycle._verify_signed_value(signed, b"x" * 32) is False
    assert lifecycle._verify_signed_value({"value": 1}, b"k" * 32) is False
    assert len(lifecycle._manifest_fingerprint({"value": 1})) == 64
    assert lifecycle._same_file(root, root) is True
    assert lifecycle._same_file(root, root / "missing") is False
    assert lifecycle._pid_exists(os.getpid()) is True
    assert lifecycle._pid_exists(-1) is False
    with pytest.raises(ValueError):
        lifecycle._validate_service_readiness_timeout(0)
    with pytest.raises(ValueError):
        lifecycle._validate_service_readiness_timeout(301)


def test_unsupported_service_adapter_rejects_every_mutation_surface() -> None:
    with pytest.raises(ValueError):
        UnsupportedServiceRegistrationAdapter(" ")
    adapter = UnsupportedServiceRegistrationAdapter("linux")
    manifest = object()
    calls = (
        lambda: adapter.inspect("service"),
        lambda: adapter.register(manifest),  # type: ignore[arg-type]
        lambda: adapter.replace(manifest, manifest),  # type: ignore[arg-type]
        lambda: adapter.unregister(manifest),  # type: ignore[arg-type]
        lambda: adapter.start_and_wait(manifest, timeout_seconds=1),  # type: ignore[arg-type]
        lambda: adapter.stop_and_wait(manifest, timeout_seconds=1),  # type: ignore[arg-type]
    )
    for call in calls:
        with pytest.raises(UnsupportedServicePlatformError, match="not qualified"):
            call()
    assert adapter.platform_id == "linux"


def _registration_manifest(tmp_path: Path) -> ServiceRegistrationManifest:
    executable = tmp_path / "artifex.exe"
    executable.write_bytes(b"artifact")
    return ServiceRegistrationManifest(
        service_id="artifex-service",
        service_version="2.0.0",
        executable=str(executable.resolve()),
        executable_sha256=registration.hashlib.sha256(b"artifact").hexdigest(),
        arguments=("service", "serve", "--state-root", str(tmp_path / "state")),
        working_directory=str(tmp_path.resolve()),
        state_root=str((tmp_path / "state").resolve()),
        activation_policy="PLATFORM_MANAGED",
    )


def test_service_registration_manifest_description_and_disk_round_trip(tmp_path: Path) -> None:
    manifest = _registration_manifest(tmp_path)
    assert ServiceRegistrationManifest.from_dict(manifest.to_dict()) == manifest
    assert registration._manifest_from_task_description(
        registration._task_description(manifest)
    ) == manifest
    registration._verify_executable(manifest)
    path = tmp_path / "registration.json"
    registration._write_manifest(path, manifest)
    assert registration.read_service_registration_manifest(path) == manifest
    registration._restore_manifest(path, manifest.canonical_bytes())
    assert path.read_bytes() == manifest.canonical_bytes()

    tampered = manifest.to_dict()
    tampered["manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="digest"):
        ServiceRegistrationManifest.from_dict(tampered)
    with pytest.raises(ServiceRegistrationDriftError, match="ownership"):
        registration._manifest_from_task_description("not-owned")
    with pytest.raises(ServiceRegistrationDriftError):
        registration._manifest_from_task_description(
            registration._TASK_DESCRIPTION_PREFIX + "not-base64"
        )


@pytest.mark.parametrize(
    "registered,digest",
    [(True, None), (True, "invalid"), (False, "0" * 64)],
)
def test_service_registration_observation_rejects_ambiguous_state(
    registered: bool, digest: str | None
) -> None:
    with pytest.raises(ValueError):
        ServiceRegistrationObservation(registered, digest)


def test_service_registration_text_xml_option_and_timeout_helpers() -> None:
    assert registration._command_text("text") == "text"
    assert registration._command_text("text".encode("utf-16")) == "text"
    assert registration._command_text(b"\xef\xbb\xbftext") == "text"
    assert registration._command_text(b"<?xml?><Task/>", xml=True).startswith("<?xml")
    assert registration._command_text("<?xml?><Task/>".encode("utf-16-le"), xml=True).startswith(
        "<?xml"
    )
    root = ET.fromstring("<Task><Name>value</Name><Parent><Child>nested</Child></Parent></Task>")
    assert registration._task_texts(root, "Name") == ("value",)
    assert registration._required_task_text(root, "Name") == "value"
    assert registration._required_task_element(root, "Parent").tag == "Parent"
    assert registration._required_child_text(root.find("Parent"), "Child") == "nested"  # type: ignore[arg-type]
    with pytest.raises(ServiceRegistrationDriftError):
        registration._required_task_text(root, "Missing")
    with pytest.raises(ServiceRegistrationDriftError):
        registration._required_task_element(root, "Missing")
    with pytest.raises(ServiceRegistrationDriftError):
        registration._required_child_text(root, "Missing")

    registration._require_option(("--state-root", "state"), "--state-root", "state")
    with pytest.raises(ValueError):
        registration._require_option((), "--state-root", "state")
    with pytest.raises(ValueError):
        registration._require_option(("--state-root", "other"), "--state-root", "state")
    registration._validate_timeout(0.1)
    registration._validate_timeout(300)
    with pytest.raises(ValueError):
        registration._validate_timeout(0)
    with pytest.raises(ValueError):
        registration._validate_timeout(301)
    assert registration._bounded_detail(
        subprocess.CompletedProcess(("command",), 1, stdout=b"", stderr=b"failure")
    ) == "failure"
