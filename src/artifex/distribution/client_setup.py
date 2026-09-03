"""Approval-gated public Codex and Claude MCP client configuration.

This module owns configuration integration only.  It never stores credentials,
never treats a vendor client as semantic authority, and never invokes a model.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from artifex import __version__
from artifex.distribution.approvals import ApprovalStore
from artifex.distribution.models import DecisionExplanation, RiskLevel
from artifex.distribution.presentation import explain_decision, require_approval

SUPPORTED_CLIENTS = frozenset({"codex", "claude"})
_CODEX_BEGIN = "# BEGIN ARTIFEX MANAGED MCP"
_CODEX_END = "# END ARTIFEX MANAGED MCP"
_AGENTS_BEGIN = "<!-- BEGIN ARTIFEX MANAGED CLIENT CONTEXT -->"
_AGENTS_END = "<!-- END ARTIFEX MANAGED CLIENT CONTEXT -->"
_RECEIPT_SCHEMA = "artifex.client-configuration-receipt/v1"
_SAFE_SKILL = re.compile(r"[a-z0-9][a-z0-9-]*")

ProcessRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class ClientConfigurationError(ValueError):
    """A client configuration cannot be changed without crossing a safety boundary."""


@dataclass(frozen=True, slots=True)
class ClientMutation:
    path: str
    kind: str
    action: str
    before_sha256: str | None
    after_sha256: str
    effect: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "action": self.action,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "effect": self.effect,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ClientMutation:
        return cls(
            _required_text(value.get("path"), "mutation path"),
            _required_text(value.get("kind"), "mutation kind"),
            _required_text(value.get("action"), "mutation action"),
            _optional_digest(value.get("before_sha256")),
            _required_digest(value.get("after_sha256"), "mutation after_sha256"),
            _required_text(value.get("effect"), "mutation effect"),
        )


@dataclass(frozen=True, slots=True)
class ClientSetupPlan:
    client: str
    project_root: str
    config_root: str
    bridge_command: tuple[str, ...]
    mutations: tuple[ClientMutation, ...]
    decision: DecisionExplanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "client": self.client,
            "project_root": self.project_root,
            "config_root": self.config_root,
            "bridge_command": list(self.bridge_command),
            "mutations": [mutation.to_dict() for mutation in self.mutations],
            "decision": self.decision.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ClientSetupPlan:
        mutations = value.get("mutations")
        command = value.get("bridge_command")
        decision = value.get("decision")
        if not isinstance(mutations, Sequence) or isinstance(mutations, (str, bytes)):
            raise ClientConfigurationError("plan mutations must be an array")
        if not isinstance(command, Sequence) or isinstance(command, (str, bytes)):
            raise ClientConfigurationError("plan bridge_command must be an array")
        if not isinstance(decision, Mapping):
            raise ClientConfigurationError("plan decision must be an object")
        if any(not isinstance(item, Mapping) for item in mutations):
            raise ClientConfigurationError("plan mutations must contain objects")
        risk = decision.get("risk")
        if risk != "REVERSIBLE":
            raise ClientConfigurationError("client configuration plans must be reversible")
        return cls(
            _normalize_client(value.get("client")),
            _required_text(value.get("project_root"), "project_root"),
            _required_text(value.get("config_root"), "config_root"),
            tuple(_required_text(item, "bridge command item") for item in command),
            tuple(ClientMutation.from_dict(item) for item in mutations),
            DecisionExplanation(
                _required_text(decision.get("action"), "decision action"),
                RiskLevel.REVERSIBLE,
                tuple(str(item) for item in decision.get("effects", ())),
                _required_text(decision.get("rollback"), "decision rollback"),
                bool(decision.get("approval_required")),
                str(decision["confirmation_token"])
                if decision.get("confirmation_token") is not None
                else None,
                _required_digest(decision.get("plan_fingerprint"), "plan fingerprint"),
                str(decision["expires_at"]) if decision.get("expires_at") is not None else None,
            ),
        )


def discover_bridge_command(executable: str | Path | None = None) -> tuple[str, ...]:
    """Resolve the shipping executable without requiring a PATH edit."""

    if executable is not None:
        candidate = Path(executable).expanduser().resolve()
    else:
        resolved = shutil.which("artifex")
        if resolved is None:
            raise ClientConfigurationError(
                "ARTIFEX launcher was not found; select the installed artifex executable"
            )
        candidate = Path(resolved).resolve()
    if not candidate.is_file():
        raise ClientConfigurationError(f"ARTIFEX launcher does not exist: {candidate}")
    return (str(candidate),)


def plan_client_enable(
    client: str,
    project_root: str | Path,
    *,
    bridge_command: Sequence[str],
    config_root: str | Path | None = None,
    approval_store: ApprovalStore | None = None,
    issue_token: bool = True,
) -> ClientSetupPlan:
    """Show every file mutation before an explicit approval can be applied."""

    normalized = _normalize_client(client)
    project = Path(project_root).expanduser().resolve()
    if not project.is_dir():
        raise ClientConfigurationError(f"project root does not exist: {project}")
    command = _normalize_command(bridge_command)
    configured_root = _client_config_root(normalized, config_root)
    desired = _desired_files(normalized, project, configured_root, command)
    mutations = tuple(
        _mutation(path, kind, content, effect) for path, kind, content, effect in desired
    )
    effects = tuple(mutation.effect for mutation in mutations)
    binding = {
        "client": normalized,
        "project_root": str(project),
        "config_root": str(configured_root),
        "bridge_command": list(command),
        "mutations": [mutation.to_dict() for mutation in mutations],
        "artifex_version": __version__,
    }
    decision = explain_decision(
        f"enable {normalized} ARTIFEX MCP integration",
        "REVERSIBLE",
        effects=effects,
        rollback="remove only ARTIFEX-managed entries after verifying post-apply hashes",
        binding=binding,
        approval_store=approval_store,
        issue_token=issue_token,
    )
    return ClientSetupPlan(
        normalized,
        str(project),
        str(configured_root),
        command,
        mutations,
        decision,
    )


def apply_client_enable(
    plan: ClientSetupPlan,
    *,
    confirmation_token: str | None,
    approval_store: ApprovalStore | None = None,
    receipt_root: str | Path | None = None,
    now: datetime | None = None,
    runner: ProcessRunner | None = None,
) -> Mapping[str, Any]:
    """Apply the approved plan atomically and persist a secret-free receipt."""

    expected = plan_client_enable(
        plan.client,
        plan.project_root,
        bridge_command=plan.bridge_command,
        config_root=plan.config_root,
        approval_store=approval_store,
        issue_token=False,
    )
    if expected.decision.plan_fingerprint != plan.decision.plan_fingerprint:
        raise PermissionError("client configuration changed after approval was issued")
    require_approval(expected.decision, confirmation_token, approval_store=approval_store)
    desired = _desired_files(
        plan.client,
        Path(plan.project_root),
        Path(plan.config_root),
        plan.bridge_command,
    )
    previous: list[tuple[Path, bytes | None]] = []
    try:
        for path, _, content, _ in desired:
            current = path.read_bytes() if path.is_file() else None
            if path.exists() and not path.is_file():
                raise ClientConfigurationError(f"configuration target is not a file: {path}")
            if path.is_symlink():
                raise ClientConfigurationError(f"configuration target may not be a symlink: {path}")
            previous.append((path, current))
            if current != content:
                _write_bytes_atomic(path, content)
    except Exception:
        for path, previous_content in reversed(previous):
            if previous_content is None:
                path.unlink(missing_ok=True)
            else:
                _write_bytes_atomic(path, previous_content)
        raise
    verification = verify_client_integration(
        plan.client,
        plan.project_root,
        bridge_command=plan.bridge_command,
        config_root=plan.config_root,
        runner=runner,
        run_processes=True,
    )
    timestamp = _as_utc(now or datetime.now(UTC)).isoformat()
    receipt = {
        "schema_version": _RECEIPT_SCHEMA,
        "receipt_id": f"client-{plan.client}-{uuid.uuid4().hex}",
        "operation": "ENABLE",
        "client": plan.client,
        "client_version": verification["client_version"],
        "artifex_version": __version__,
        "project_root": plan.project_root,
        "config_root": plan.config_root,
        "bridge_command": list(plan.bridge_command),
        "plan_fingerprint": plan.decision.plan_fingerprint,
        "recorded_at": timestamp,
        "mutations": [mutation.to_dict() for mutation in expected.mutations],
        "verification": verification,
        "secret_material_present": False,
        "rollback_available": True,
    }
    output_root = (
        Path(receipt_root).expanduser().resolve()
        if receipt_root is not None
        else Path(plan.project_root) / ".artifex" / "integration-receipts"
    )
    output = output_root / f"{receipt['receipt_id']}.json"
    _write_bytes_atomic(output, _json_bytes(receipt))
    return {**receipt, "receipt_path": str(output)}


def verify_client_integration(
    client: str,
    project_root: str | Path,
    *,
    bridge_command: Sequence[str],
    config_root: str | Path | None = None,
    runner: ProcessRunner | None = None,
    run_processes: bool = True,
) -> Mapping[str, Any]:
    """Verify local configuration and bounded bridge/client discovery probes."""

    normalized = _normalize_client(client)
    project = Path(project_root).expanduser().resolve()
    command = _normalize_command(bridge_command)
    configured_root = _client_config_root(normalized, config_root)
    desired = _desired_files(normalized, project, configured_root, command)
    file_checks = []
    for path, kind, content, _ in desired:
        actual = path.read_bytes() if path.is_file() else None
        file_checks.append(
            {
                "path": str(path),
                "kind": kind,
                "status": "PASS" if actual == content else "FAIL",
                "actual_sha256": _sha256(actual) if actual is not None else None,
                "expected_sha256": _sha256(content),
            }
        )
    client_executable = shutil.which(normalized)
    client_version: str | None = None
    bridge_status = "NOT_RUN"
    client_registration = "NOT_RUN"
    diagnostics: list[str] = []
    process_runner = _run_process if runner is None else runner
    if run_processes:
        bridge = process_runner((*command, "mcp", "test"))
        bridge_status = "PASS" if bridge.returncode == 0 else "FAIL"
        if bridge.returncode != 0:
            diagnostics.append(_friendly_process_error("ARTIFEX MCP bridge", bridge))
        if client_executable is not None:
            version = process_runner((client_executable, "--version"))
            if version.returncode == 0:
                client_version = (version.stdout or version.stderr).strip()[:200]
            registration = (
                _run_process(
                    (client_executable, "mcp", "get", "artifex"), cwd=project
                )
                if runner is None
                else runner((client_executable, "mcp", "get", "artifex"))
            )
            client_registration = "PASS" if registration.returncode == 0 else "FAIL"
            if registration.returncode != 0:
                diagnostics.append(
                    _friendly_process_error(f"{normalized} registration", registration)
                )
        else:
            client_registration = "CLIENT_NOT_FOUND"
            diagnostics.append(
                f"{normalized} client was not found. Install it or select its executable; "
                "ARTIFEX did not change PATH or PowerShell ExecutionPolicy."
            )
    configured = all(item["status"] == "PASS" for item in file_checks)
    ready = configured and (
        not run_processes
        or (
            bridge_status == "PASS"
            and client_executable is not None
            and client_registration == "PASS"
        )
    )
    return {
        "client": normalized,
        "status": "READY" if ready else "NEEDS_ATTENTION",
        "configured": configured,
        "client_detected": client_executable is not None,
        "client_executable": client_executable,
        "client_version": client_version,
        "bridge_status": bridge_status,
        "client_registration": client_registration,
        "live_model_invocation": False,
        "checks": file_checks,
        "diagnostics": diagnostics,
    }


def plan_client_rollback(
    receipt_path: str | Path,
    *,
    approval_store: ApprovalStore | None = None,
    issue_token: bool = True,
) -> Mapping[str, Any]:
    receipt_path_value = Path(receipt_path).expanduser().resolve()
    receipt = _load_receipt(receipt_path_value)
    mutations = receipt["mutations"]
    effects = tuple(f"remove ARTIFEX-managed entry from {item['path']}" for item in mutations)
    decision = explain_decision(
        f"rollback {receipt['client']} ARTIFEX MCP integration",
        "REVERSIBLE",
        effects=effects,
        rollback="rerun the approval-gated client enable plan",
        binding={
            "receipt_path": str(receipt_path_value),
            "receipt_sha256": _sha256(receipt_path_value.read_bytes()),
            "receipt_id": receipt["receipt_id"],
            "mutations": mutations,
        },
        approval_store=approval_store,
        issue_token=issue_token,
    )
    return {"receipt_path": str(receipt_path_value), "decision": decision.to_dict()}


def apply_client_rollback(
    rollback_plan: Mapping[str, Any],
    *,
    confirmation_token: str | None,
    approval_store: ApprovalStore | None = None,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    path = Path(_required_text(rollback_plan.get("receipt_path"), "receipt_path")).resolve()
    expected = plan_client_rollback(path, approval_store=approval_store, issue_token=False)
    supplied = rollback_plan.get("decision")
    if not isinstance(supplied, Mapping):
        raise ClientConfigurationError("rollback plan decision must be an object")
    if supplied.get("plan_fingerprint") != expected["decision"]["plan_fingerprint"]:
        raise PermissionError("rollback plan or receipt changed after approval was issued")
    decision = DecisionExplanation(
        str(expected["decision"]["action"]),
        RiskLevel.REVERSIBLE,
        tuple(str(item) for item in expected["decision"]["effects"]),
        str(expected["decision"]["rollback"]),
        True,
        None,
        str(expected["decision"]["plan_fingerprint"]),
        None,
    )
    require_approval(decision, confirmation_token, approval_store=approval_store)
    receipt = _load_receipt(path)
    prepared: list[tuple[ClientMutation, Path, bytes | None]] = []
    for raw in reversed(receipt["mutations"]):
        mutation = ClientMutation.from_dict(raw)
        target = Path(mutation.path)
        current = target.read_bytes() if target.is_file() else None
        current_hash = _sha256(current) if current is not None else None
        if current_hash != mutation.after_sha256:
            raise ClientConfigurationError(
                f"rollback stopped because configuration drifted after apply: {target}"
            )
        prepared.append((mutation, target, current))
    restored: list[Mapping[str, Any]] = []
    try:
        for mutation, target, _current in prepared:
            if mutation.action == "UNCHANGED":
                restored.append(
                    {"path": str(target), "restored_sha256": mutation.before_sha256}
                )
                continue
            restored_content = _rollback_content(target, mutation, receipt)
            if restored_content is None:
                target.unlink(missing_ok=True)
            else:
                _write_bytes_atomic(target, restored_content)
            observed = target.read_bytes() if target.is_file() else None
            observed_hash = _sha256(observed) if observed is not None else None
            if observed_hash != mutation.before_sha256:
                raise ClientConfigurationError(f"rollback verification failed: {target}")
            restored.append({"path": str(target), "restored_sha256": observed_hash})
    except Exception:
        for _, target, post_apply_content in reversed(prepared):
            if post_apply_content is None:
                target.unlink(missing_ok=True)
            else:
                _write_bytes_atomic(target, post_apply_content)
        raise
    result = {
        "schema_version": _RECEIPT_SCHEMA,
        "receipt_id": f"rollback-{receipt['client']}-{uuid.uuid4().hex}",
        "operation": "ROLLBACK",
        "source_receipt_id": receipt["receipt_id"],
        "client": receipt["client"],
        "recorded_at": _as_utc(now or datetime.now(UTC)).isoformat(),
        "status": "PASS",
        "restored": restored,
        "secret_material_present": False,
    }
    output = path.parent / f"{result['receipt_id']}.json"
    _write_bytes_atomic(output, _json_bytes(result))
    return {**result, "receipt_path": str(output)}


def _desired_files(
    client: str,
    project: Path,
    config_root: Path,
    command: tuple[str, ...],
) -> tuple[tuple[Path, str, bytes, str], ...]:
    if client == "codex":
        return _codex_desired_files(project, config_root, command)
    return _claude_desired_files(project, command)


def _codex_desired_files(
    project: Path, config_root: Path, command: tuple[str, ...]
) -> tuple[tuple[Path, str, bytes, str], ...]:
    config = config_root / "config.toml"
    existing = config.read_bytes() if config.is_file() else b""
    text = existing.decode("utf-8")
    block = _codex_mcp_block(command)
    desired_config = _replace_managed_block(text, _CODEX_BEGIN, _CODEX_END, block)
    if _CODEX_BEGIN not in text and re.search(r"(?m)^\s*\[mcp_servers\.artifex\]\s*$", text):
        raise ClientConfigurationError(
            "Codex already has an unmanaged artifex MCP entry; review it before enabling ARTIFEX"
        )
    agents = project / "AGENTS.md"
    agents_text = agents.read_bytes().decode("utf-8") if agents.is_file() else ""
    desired_agents = _replace_managed_block(
        agents_text,
        _AGENTS_BEGIN,
        _AGENTS_END,
        _agents_block("Codex", ".agents/skills/artifex-*"),
    )
    values: list[tuple[Path, str, bytes, str]] = [
        (
            config,
            "codex-config",
            desired_config.encode("utf-8"),
            f"configure ARTIFEX MCP in current Codex config {config}",
        ),
        (
            agents,
            "managed-text-block",
            desired_agents.encode("utf-8"),
            f"add scoped ARTIFEX guidance to {agents}",
        ),
    ]
    pack = _interface_pack("codex") / "skills"
    for skill in sorted(path for path in pack.iterdir() if path.is_dir()):
        if not _SAFE_SKILL.fullmatch(skill.name):
            raise ClientConfigurationError(f"unsafe bundled skill name: {skill.name}")
        source = skill / "SKILL.md"
        target = project / ".agents" / "skills" / f"artifex-{skill.name}" / "SKILL.md"
        content = source.read_bytes()
        if target.is_file() and target.read_bytes() != content:
            raise ClientConfigurationError(f"Codex skill target already differs: {target}")
        values.append(
            (target, "managed-file", content, f"install discoverable Codex skill {target}")
        )
    return tuple(values)


def _claude_desired_files(
    project: Path, command: tuple[str, ...]
) -> tuple[tuple[Path, str, bytes, str], ...]:
    config = project / ".mcp.json"
    value: dict[str, Any] = {}
    original = b""
    if config.is_file():
        original = config.read_bytes()
        try:
            loaded = json.loads(original.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ClientConfigurationError(f"Claude .mcp.json is invalid: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ClientConfigurationError("Claude .mcp.json must contain an object")
        value = loaded
    servers = value.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ClientConfigurationError("Claude mcpServers must be an object")
    desired_entry = {
        "type": "stdio",
        "command": command[0],
        "args": [*command[1:], "mcp", "serve"],
    }
    previous = servers.get("artifex")
    if previous is not None and previous != desired_entry:
        raise ClientConfigurationError(
            "Claude already has an unmanaged artifex MCP entry; review it before enabling ARTIFEX"
        )
    servers["artifex"] = desired_entry
    if previous == desired_entry:
        desired_content = original
    elif not original:
        desired_content = _json_bytes(value)
    else:
        desired_content = _insert_claude_entry(
            original, desired_entry, bool(servers.keys() - {"artifex"})
        )
    values: list[tuple[Path, str, bytes, str]] = [
        (
            config,
            "claude-mcp-json",
            desired_content,
            f"configure ARTIFEX in Claude project MCP configuration {config}",
        )
    ]
    pack = _interface_pack("claude")
    for relative in (
        Path(".claude/rules/artifex.md"),
        Path(".claude/skills/artifex/SKILL.md"),
    ):
        source = pack / relative
        target = project / relative
        content = source.read_bytes()
        if target.is_file() and target.read_bytes() != content:
            raise ClientConfigurationError(f"Claude interface target already differs: {target}")
        values.append((target, "managed-file", content, f"install Claude interface file {target}"))
    return tuple(values)


def _rollback_content(
    path: Path, mutation: ClientMutation, receipt: Mapping[str, Any]
) -> bytes | None:
    kind = mutation.kind
    if kind == "codex-config":
        return _remove_managed_block(
            path.read_bytes().decode("utf-8"),
            _CODEX_BEGIN,
            _CODEX_END,
            mutation.before_sha256,
        )
    if kind == "managed-text-block":
        return _remove_managed_block(
            path.read_bytes().decode("utf-8"),
            _AGENTS_BEGIN,
            _AGENTS_END,
            mutation.before_sha256,
        )
    if kind == "claude-mcp-json":
        command = receipt.get("bridge_command")
        if not isinstance(command, list) or not command:
            raise ClientConfigurationError("receipt bridge command is invalid")
        entry = {
            "type": "stdio",
            "command": command[0],
            "args": [*command[1:], "mcp", "serve"],
        }
        return _remove_claude_entry(path.read_bytes(), entry, mutation.before_sha256)
    if kind == "managed-file":
        return None
    raise ClientConfigurationError(f"unsupported rollback mutation kind: {kind}")


def _codex_mcp_block(command: tuple[str, ...]) -> str:
    args = [*command[1:], "mcp", "serve"]
    return (
        f"{_CODEX_BEGIN}\n"
        "[mcp_servers.artifex]\n"
        f"command = {json.dumps(command[0])}\n"
        f"args = {json.dumps(args)}\n"
        "enabled = true\n"
        f"{_CODEX_END}"
    )


def _agents_block(client: str, skills: str) -> str:
    return (
        f"{_AGENTS_BEGIN}\n"
        f"## ARTIFEX {client} integration\n\n"
        "Treat `.artifex/project-model.json` and accepted repository artifacts as authority.\n"
        f"Use `{skills}` as workflow guidance; client memory and transcripts are auxiliary.\n"
        "Do not infer acceptance from an executor or MCP response.\n"
        f"{_AGENTS_END}"
    )


def _replace_managed_block(text: str, begin: str, end: str, block: str) -> str:
    if (begin in text) != (end in text):
        raise ClientConfigurationError("ARTIFEX managed configuration markers are incomplete")
    if begin in text:
        pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
        if len(pattern.findall(text)) != 1:
            raise ClientConfigurationError("ARTIFEX managed configuration markers are ambiguous")
        observed = pattern.findall(text)[0]
        if observed != block:
            raise ClientConfigurationError(
                "an older or different ARTIFEX managed block exists; rollback it before replacing"
            )
        return text
    if not text:
        return block + "\n"
    separator = "" if text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
    return text + separator + block + "\n"


def _remove_managed_block(
    text: str, begin: str, end: str, before_sha256: str | None
) -> bytes | None:
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", re.DOTALL)
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise ClientConfigurationError("managed configuration block is missing or ambiguous")
    raw = pattern.sub("", text)
    candidates = [raw.encode("utf-8")]
    for count in (1, 2):
        if raw.endswith("\n" * count):
            candidates.append(raw[:-count].encode("utf-8"))
    if before_sha256 is None:
        return None
    for candidate in candidates:
        if _sha256(candidate) == before_sha256:
            return candidate
    raise ClientConfigurationError("managed block removal cannot reproduce the pre-apply file")


def _insert_claude_entry(
    original: bytes, entry: Mapping[str, Any], has_other_servers: bool
) -> bytes:
    text = original.decode("utf-8")
    fragment = '"artifex":' + json.dumps(entry, sort_keys=True, separators=(",", ":"))
    server_matches = list(re.finditer(r'"mcpServers"\s*:\s*\{', text))
    if server_matches:
        if len(server_matches) != 1:
            raise ClientConfigurationError("Claude mcpServers location is ambiguous")
        index = server_matches[0].end()
        insertion = fragment + ("," if has_other_servers else "")
    else:
        opening = text.find("{")
        if opening < 0:
            raise ClientConfigurationError("Claude .mcp.json has no top-level object")
        index = opening + 1
        has_top_level = bool(json.loads(text))
        insertion = '"mcpServers":{' + fragment + "}" + ("," if has_top_level else "")
    result = (text[:index] + insertion + text[index:]).encode("utf-8")
    parsed = json.loads(result)
    if parsed.get("mcpServers", {}).get("artifex") != entry:
        raise ClientConfigurationError("Claude MCP insertion could not be verified")
    return result


def _remove_claude_entry(
    current: bytes, entry: Mapping[str, Any], before_sha256: str | None
) -> bytes | None:
    text = current.decode("utf-8")
    fragment = '"artifex":' + json.dumps(entry, sort_keys=True, separators=(",", ":"))
    candidates = [
        text.replace(fragment + ",", "", 1).encode("utf-8"),
        text.replace(fragment, "", 1).encode("utf-8"),
        text.replace('"mcpServers":{' + fragment + "},", "", 1).encode("utf-8"),
        text.replace('"mcpServers":{' + fragment + "}", "", 1).encode("utf-8"),
    ]
    if before_sha256 is None:
        return None
    for candidate in candidates:
        if _sha256(candidate) == before_sha256:
            return candidate
    raise ClientConfigurationError("Claude rollback cannot reproduce the pre-apply file")


def _mutation(path: Path, kind: str, content: bytes, effect: str) -> ClientMutation:
    before = path.read_bytes() if path.is_file() else None
    if path.exists() and not path.is_file():
        raise ClientConfigurationError(f"configuration target is not a file: {path}")
    action = "UNCHANGED" if before == content else ("CREATE" if before is None else "UPDATE")
    return ClientMutation(
        str(path),
        kind,
        action,
        _sha256(before) if before is not None else None,
        _sha256(content),
        effect,
    )


def _load_receipt(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ClientConfigurationError(f"cannot read client receipt: {exc}") from exc
    if not isinstance(value, Mapping) or value.get("schema_version") != _RECEIPT_SCHEMA:
        raise ClientConfigurationError("unsupported client receipt")
    if value.get("secret_material_present") is not False:
        raise ClientConfigurationError("client receipt is not certified secret-free")
    mutations = value.get("mutations")
    if not isinstance(mutations, list) or not mutations:
        raise ClientConfigurationError("client receipt has no mutations")
    return value


def _interface_pack(client: str) -> Path:
    source = Path(__file__).resolve().parents[3] / "interface_packs" / client
    if source.is_dir():
        return source
    packaged = Path(__file__).resolve().parents[1] / "interface_packs" / client
    if packaged.is_dir():
        return packaged
    standalone = Path(sys.executable).resolve().parent / "interface_packs" / client
    if standalone.is_dir():
        return standalone
    raise ClientConfigurationError(f"bundled {client} interface pack is missing")


def _client_config_root(client: str, value: str | Path | None) -> Path:
    if value is not None:
        return Path(value).expanduser().resolve()
    if client == "codex":
        return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser().resolve()
    return Path.home().resolve()


def _normalize_client(value: object) -> str:
    if not isinstance(value, str) or value.casefold() not in SUPPORTED_CLIENTS:
        raise ClientConfigurationError("client must be codex or claude")
    return value.casefold()


def _normalize_command(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not value:
        raise ClientConfigurationError("bridge command must be a non-empty argument array")
    command = tuple(_required_text(item, "bridge command item") for item in value)
    executable = Path(command[0]).expanduser()
    if not executable.is_absolute():
        raise ClientConfigurationError("bridge executable must be an absolute installed path")
    return (str(executable.resolve()), *command[1:])


def _write_bytes_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _run_process(
    arguments: Sequence[str], *, cwd: str | Path | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            shell=False,
            cwd=cwd,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(arguments, 127, "", f"{type(exc).__name__}: {exc}")


def _friendly_process_error(label: str, result: subprocess.CompletedProcess[str]) -> str:
    detail = (result.stderr or result.stdout or "no diagnostic output").strip()[:300]
    return f"{label} check failed (exit {result.returncode}): {detail}"


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ClientConfigurationError(f"{name} must be a non-empty string")
    return value


def _required_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ClientConfigurationError(f"{name} must be a SHA-256 digest")
    return value


def _optional_digest(value: object) -> str | None:
    return None if value is None else _required_digest(value, "optional digest")


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
