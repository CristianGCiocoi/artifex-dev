"""Bounded, read-only live provider interaction."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artifex.capabilities.evidence import CapabilityEvidenceStore, CapabilityReceipt
from artifex.capabilities.models import ProviderInstance, ProviderRole

InteractionRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]
_MAX_RESPONSE_BYTES = 64 * 1024
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_SECRETS = (
    (re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{12,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
)


@dataclass(frozen=True, slots=True)
class RepositoryBaseline:
    git_head: str
    git_state_sha256: str
    project_model_sha256: str
    setup_sha256: str

    @property
    def fingerprint(self) -> str:
        return _sha256_json(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {
            "git_head": self.git_head,
            "git_state_sha256": self.git_state_sha256,
            "project_model_sha256": self.project_model_sha256,
            "setup_sha256": self.setup_sha256,
        }


class ProviderInteractionService:
    def __init__(
        self,
        *,
        store: CapabilityEvidenceStore | None = None,
        runner: InteractionRunner | None = None,
        timeout_seconds: float = 300,
    ) -> None:
        if not 0 < timeout_seconds <= 3600:
            raise ValueError("interaction timeout must be between 0 and 3600 seconds")
        self.store = store or CapabilityEvidenceStore()
        self.runner = runner or self._run
        self.timeout_seconds = timeout_seconds

    def interact(
        self,
        *,
        provider: ProviderInstance,
        project_root: str | Path,
        project_id: str,
        project_job_id: str,
        prompt: str,
    ) -> dict[str, object]:
        if provider.provider_id not in {"codex", "claude"}:
            raise ValueError("INTERACTION requires a supported configured provider")
        if ProviderRole.INTERACTION not in provider.certified_roles:
            raise ValueError("provider is not role-conformant for INTERACTION")
        if not prompt.strip():
            raise ValueError("interaction prompt is required")
        root = Path(project_root).expanduser().resolve()
        self._assert_external_store(root)
        baseline = _capture_baseline(root)
        command = _interaction_command(provider, root, prompt)
        try:
            completed = self.runner(command, root)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(
                f"{provider.provider_id} interaction failed: {type(exc).__name__}"
            ) from exc
        if completed.returncode != 0:
            raise ValueError(
                f"{provider.provider_id} interaction exited with {completed.returncode}"
            )
        response = (
            _final_agent_response(completed.stdout)
            if provider.provider_id == "codex"
            else _final_claude_response(completed.stdout)
        )
        after = _capture_baseline(root)
        if after != baseline:
            raise ValueError(
                f"{provider.provider_id} read-only interaction changed the Git or Project baseline"
            )
        sanitized, truncated = _sanitize_response(response)
        receipt = CapabilityReceipt.issue(
            provider_id=provider.provider_id,
            role=ProviderRole.INTERACTION,
            project_id=project_id,
            project_job_id=project_job_id,
            input_sha256=_sha256_text(prompt),
            output_sha256=_sha256_text(sanitized),
            baseline_sha256=baseline.fingerprint,
        )
        self.store.append(receipt)
        return {
            "provider_id": provider.provider_id,
            "role": ProviderRole.INTERACTION.value,
            "live": True,
            "simulated": False,
            "response": sanitized,
            "response_truncated": truncated,
            "receipt": receipt.to_dict(),
            "baseline": baseline.to_dict(),
            "canonical_acceptance": False,
        }

    def _assert_external_store(self, project_root: Path) -> None:
        try:
            self.store.path.relative_to(project_root)
        except ValueError:
            return
        raise ValueError("capability evidence store must remain outside Project Git")

    def _run(self, arguments: Sequence[str], root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(arguments),
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_seconds,
        )


def _interaction_command(provider: ProviderInstance, root: Path, prompt: str) -> tuple[str, ...]:
    command = provider.readiness.command or provider.configuration.command
    if provider.provider_id == "claude":
        prefix = _validated_claude_prefix(command)
        return (
            *prefix,
            "--print",
            "--output-format",
            "json",
            "--permission-mode",
            "plan",
            "--strict-mcp-config",
            "--tools",
            "Read,Glob,Grep",
            prompt,
        )
    prefix = _validated_codex_prefix(command)
    return (
        *prefix,
        "exec",
        *_windows_sandbox_override(),
        "--sandbox",
        "read-only",
        "--ephemeral",
        "--json",
        "--color",
        "never",
        "-C",
        str(root),
        prompt,
    )


def _windows_sandbox_override() -> tuple[str, ...]:
    # Codex documents unelevated as the supported fallback when administrator-
    # approved native setup is unavailable. It retains ACL filesystem bounds.
    return ("-c", 'windows.sandbox="unelevated"') if os.name == "nt" else ()


def _validated_codex_prefix(command: Sequence[str]) -> tuple[str, ...]:
    if not command or any(
        not isinstance(item, str) or not item or "\x00" in item for item in command
    ):
        raise ValueError("configured Codex command vector is invalid")
    normalized = tuple(command)
    executable = Path(normalized[0]).name.casefold()
    if executable in {"codex", "codex.exe", "codex.cmd"}:
        if len(normalized) != 1:
            raise ValueError("configured Codex command cannot pre-supply caller flags")
        return normalized
    if executable not in {"npx", "npx.exe", "npx.cmd"}:
        raise ValueError("configured command must invoke Codex")
    if len(normalized) != 3 or normalized[1] != "--yes":
        raise ValueError("configured npx Codex command must be pinned and non-interactive")
    if re.fullmatch(r"@openai/codex@\d+\.\d+\.\d+", normalized[2]) is None:
        raise ValueError("configured npx Codex package must pin an exact version")
    return normalized


def _validated_claude_prefix(command: Sequence[str]) -> tuple[str, ...]:
    if not command or any(
        not isinstance(item, str) or not item or "\x00" in item for item in command
    ):
        raise ValueError("configured Claude command vector is invalid")
    normalized = tuple(command)
    executable = Path(normalized[0]).name.casefold()
    if executable in {"claude", "claude.exe", "claude.cmd"}:
        if len(normalized) != 1:
            raise ValueError("configured Claude command cannot pre-supply caller flags")
        return normalized
    if executable not in {"npx", "npx.exe", "npx.cmd"}:
        raise ValueError("configured command must invoke Claude")
    if len(normalized) != 3 or normalized[1] != "--yes":
        raise ValueError("configured npx Claude command must be pinned and non-interactive")
    if re.fullmatch(r"@anthropic-ai/claude-code@\d+\.\d+\.\d+", normalized[2]) is None:
        raise ValueError("configured npx Claude package must pin an exact version")
    return normalized


def _capture_baseline(root: Path) -> RepositoryBaseline:
    top = _git(root, "rev-parse", "--show-toplevel")
    if Path(top).resolve() != root:
        raise ValueError("project_root must be the exact Git worktree root")
    head = _git_head(root)
    git_state = {
        "status": _git(root, "status", "--porcelain=v2", "--untracked-files=all", allow_empty=True),
        "diff": _git(root, "diff", "--no-ext-diff", "--binary", allow_empty=True),
        "cached_diff": _git(
            root, "diff", "--cached", "--no-ext-diff", "--binary", allow_empty=True
        ),
    }
    model = root / ".artifex" / "project-model.json"
    setup = root / ".artifex" / "integrations.json"
    if not model.is_file() or not setup.is_file():
        raise ValueError("persisted Project Model and provider setup are required")
    return RepositoryBaseline(
        git_head=head,
        git_state_sha256=_sha256_json(git_state),
        project_model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),
        setup_sha256=hashlib.sha256(setup.read_bytes()).hexdigest(),
    )


def _git(root: Path, *arguments: str, allow_empty: bool = False) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    value = completed.stdout.rstrip("\r\n")
    if completed.returncode != 0 or (not allow_empty and not value):
        detail = completed.stderr.strip() or "unknown Git inspection failure"
        raise ValueError(f"read-only Git inspection failed: {detail}")
    return value


def _git_head(root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if completed.returncode == 0 and completed.stdout.strip():
        return completed.stdout.strip()
    # A newly created ARTIFEX Project may have an initialized, unborn branch.
    symbolic = _git(root, "symbolic-ref", "--short", "HEAD")
    return f"UNBORN:{symbolic}"


def _final_agent_response(output: str) -> str:
    responses: list[str] = []
    thread_started = 0
    turn_started = 0
    turn_completed = 0
    terminal = False
    for line in output.splitlines():
        if not line.strip():
            raise ValueError("Codex JSONL contained an empty record")
        try:
            event = json.loads(line, object_pairs_hook=_unique_object)
        except json.JSONDecodeError:
            raise ValueError("Codex JSONL was malformed or ambiguous") from None
        if not isinstance(event, Mapping):
            raise ValueError("Codex JSONL records must be objects")
        event_type = event.get("type")
        if terminal:
            raise ValueError("Codex JSONL continued after the completed turn")
        if event_type in {"turn.failed", "error"}:
            raise ValueError("Codex interaction reported a failed turn")
        if event_type == "thread.started":
            thread_started += 1
        if event_type == "turn.started":
            turn_started += 1
        if event_type == "turn.completed":
            turn_completed += 1
            terminal = True
        if event_type != "item.completed":
            continue
        item = event.get("item")
        if not isinstance(item, Mapping) or item.get("type") != "agent_message":
            continue
        text = item.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Codex final agent response was empty")
        responses.append(text)
    if (thread_started, turn_started, turn_completed) != (1, 1, 1) or not responses:
        raise ValueError("Codex interaction requires exactly one final agent response")
    # Codex may emit user-visible progress messages as agent_message items. The
    # last one immediately preceding the sole turn.completed event is the one
    # final response; earlier messages are not final authority.
    return responses[-1]


def _final_claude_response(output: str) -> str:
    try:
        value = json.loads(output, object_pairs_hook=_unique_object)
    except json.JSONDecodeError:
        raise ValueError("Claude interaction JSON was malformed or ambiguous") from None
    if not isinstance(value, Mapping) or value.get("is_error") is True:
        raise ValueError("Claude interaction did not produce a successful result")
    response = value.get("result")
    if not isinstance(response, str) or not response.strip():
        raise ValueError("Claude final response was empty")
    return response


def _sanitize_response(value: str) -> tuple[str, bool]:
    sanitized = _ANSI.sub("", value)
    sanitized = "".join(
        character for character in sanitized if character in "\n\r\t" or ord(character) >= 32
    )
    for pattern, replacement in _SECRETS:
        sanitized = pattern.sub(replacement, sanitized)
    encoded = sanitized.encode("utf-8")
    if len(encoded) <= _MAX_RESPONSE_BYTES:
        return sanitized.strip(), False
    clipped = encoded[:_MAX_RESPONSE_BYTES].decode("utf-8", errors="ignore").rstrip()
    return f"{clipped}\n[OUTPUT TRUNCATED]", True


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise json.JSONDecodeError("duplicate object key", key, 0)
        value[key] = item
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = ["ProviderInteractionService", "RepositoryBaseline"]
