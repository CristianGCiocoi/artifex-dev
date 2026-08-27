"""Fresh-process provider setup loading and live Capability Graph composition."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from artifex.capabilities.credentials import AuthenticationAssertion, CredentialBroker
from artifex.capabilities.models import (
    CredentialReference,
    GovernanceMode,
    ProviderConfiguration,
    ProviderInstance,
    ProviderReadiness,
    ProviderRole,
    ReadinessState,
)
from artifex.capabilities.registry import CapabilityGraph, CapabilityRegistry
from artifex.distribution.setup import SETUP_STATE_PATH
from artifex.integrations.claude import CLAUDE_CAPABILITIES, ClaudeDetection
from artifex.integrations.codex import CODEX_CAPABILITIES, CodexDetection
from artifex.integrations.deepseek import DeepSeekDetection, detect_deepseek

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
_VERSION = re.compile(r"(?<!\d)(\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?)")
_CLAUDE_MINIMUM = (2, 1, 3)
_CLAUDE_MAXIMUM_EXCLUSIVE = (3, 0, 0)


class ProviderSetupError(ValueError):
    pass


class ProviderCompositionLoader:
    """Load persisted opt-in, perform probes, and build the runtime graph."""

    def __init__(
        self,
        *,
        which: Callable[[str], str | None] = shutil.which,
        runner: CommandRunner | None = None,
        credential_broker: CredentialBroker | None = None,
        certified_roles: Mapping[str, frozenset[ProviderRole]] | None = None,
    ) -> None:
        self.which = which
        self.runner = runner
        self.credential_broker = credential_broker or CredentialBroker(
            {
                "codex-native-session": self._probe_codex_native_session,
                "claude-native-session": self._probe_claude_native_session,
                "deepseek-native-session": self._probe_deepseek_native_session,
            }
        )
        self.certified_roles = dict(certified_roles or {})

    def load(self, project_root: str | Path) -> CapabilityGraph:
        root = Path(project_root).expanduser().resolve()
        state_path = root / SETUP_STATE_PATH
        registry = CapabilityRegistry()
        if not state_path.is_file():
            return registry.graph(source=str(state_path))
        value = self._load_state(state_path)
        for configuration in self._configurations(value):
            if not configuration.enabled:
                continue
            if configuration.provider_id == "codex":
                registry.register(self._compose_codex(configuration))
            elif configuration.provider_id == "claude":
                registry.register(self._compose_claude(configuration))
            elif configuration.provider_id == "deepseek":
                registry.register(self._compose_deepseek(configuration))
        return registry.graph(source=str(state_path))

    @staticmethod
    def _load_state(path: Path) -> Mapping[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderSetupError(f"provider setup is unreadable: {type(exc).__name__}") from exc
        if not isinstance(value, Mapping):
            raise ProviderSetupError("provider setup must be an object")
        if value.get("authority") != "ARTIFEX_PROJECT_STATE":
            raise ProviderSetupError("provider setup authority is invalid")
        return value

    def _configurations(self, value: Mapping[str, Any]) -> tuple[ProviderConfiguration, ...]:
        schema_version = value.get("schema_version")
        if schema_version == "1.0":
            enabled = self._string_array(value.get("enabled"), "enabled")
            return tuple(self._default_configuration(identifier) for identifier in enabled)
        if schema_version != "2.0":
            raise ProviderSetupError("unsupported provider setup schema")
        providers = value.get("providers")
        if not isinstance(providers, list):
            raise ProviderSetupError("provider setup providers must be an array")
        return tuple(self._configuration(item) for item in providers)

    def _configuration(self, value: object) -> ProviderConfiguration:
        if not isinstance(value, Mapping):
            raise ProviderSetupError("provider setup entry must be an object")
        allowed = {
            "provider_id",
            "enabled",
            "roles",
            "governance_mode",
            "command",
            "credential_reference",
        }
        if set(value) - allowed:
            raise ProviderSetupError("provider setup entry contains unknown fields")
        provider_id = self._string(value.get("provider_id"), "provider_id")
        roles = frozenset(
            ProviderRole(item) for item in self._string_array(value.get("roles"), "roles")
        )
        reference_value = value.get("credential_reference")
        reference = (
            self._credential_reference(reference_value, provider_id)
            if reference_value is not None
            else None
        )
        enabled = value.get("enabled")
        if not isinstance(enabled, bool):
            raise ProviderSetupError("provider enabled must be a boolean")
        return ProviderConfiguration(
            provider_id=provider_id,
            enabled=enabled,
            roles=roles,
            governance_mode=GovernanceMode(
                self._string(value.get("governance_mode"), "governance_mode")
            ),
            command=self._string_array(value.get("command"), "command"),
            credential_reference=reference,
        )

    @staticmethod
    def _credential_reference(value: object, provider_id: str) -> CredentialReference:
        if not isinstance(value, Mapping):
            raise ProviderSetupError("credential_reference must be an object")
        if set(value) != {
            "broker",
            "reference",
            "provider_id",
            "scopes",
            "secret_material_present",
        }:
            raise ProviderSetupError("credential_reference fields are invalid")
        if value.get("secret_material_present") is not False:
            raise ProviderSetupError("credential reference cannot contain secret material")
        observed_provider = ProviderCompositionLoader._string(
            value.get("provider_id"), "credential provider_id"
        )
        if observed_provider != provider_id:
            raise ProviderSetupError("credential reference provider does not match setup")
        return CredentialReference(
            broker=ProviderCompositionLoader._string(value.get("broker"), "credential broker"),
            reference=ProviderCompositionLoader._string(
                value.get("reference"), "credential reference"
            ),
            provider_id=provider_id,
            scopes=ProviderCompositionLoader._string_array(value.get("scopes"), "scopes"),
        )

    def _default_configuration(self, provider_id: str) -> ProviderConfiguration:
        if provider_id == "codex":
            return ProviderConfiguration(
                provider_id="codex",
                enabled=True,
                roles=frozenset(
                    {ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER}
                ),
                governance_mode=GovernanceMode.STANDALONE,
                command=("codex",),
                credential_reference=CredentialReference(
                    "codex-native-session",
                    "default",
                    "codex",
                    ("INTERACTION", "EXECUTION_IMPLEMENTER"),
                ),
            )
        if provider_id == "claude":
            return ProviderConfiguration(
                provider_id="claude",
                enabled=True,
                roles=frozenset(
                    {ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER}
                ),
                governance_mode=GovernanceMode.STANDALONE,
                command=("claude",),
                credential_reference=CredentialReference(
                    "claude-native-session",
                    "default",
                    "claude",
                    ("INTERACTION", "EXECUTION_IMPLEMENTER"),
                ),
            )
        if provider_id == "deepseek":
            return ProviderConfiguration(
                provider_id="deepseek",
                enabled=True,
                roles=frozenset({ProviderRole.EXECUTION_IMPLEMENTER}),
                governance_mode=GovernanceMode.PROVIDER_MANAGED,
                command=("deepseek",),
                credential_reference=CredentialReference(
                    "deepseek-native-session",
                    "default",
                    "deepseek",
                    ("EXECUTION_IMPLEMENTER",),
                ),
            )
        return ProviderConfiguration(
            provider_id=provider_id,
            enabled=True,
            roles=frozenset({ProviderRole.INTERACTION}),
            governance_mode=GovernanceMode.STANDALONE,
            command=(provider_id,),
        )

    def _compose_codex(self, configuration: ProviderConfiguration) -> ProviderInstance:
        detection, command = self._detect_codex(configuration.command)
        checks = {
            "detected": detection.available,
            "configured": configuration.enabled,
            "authenticated": False,
            "healthy": False,
            "registered": False,
            "available": False,
        }
        state = ReadinessState.NOT_DETECTED
        detail = detection.error or "Codex was not detected"
        assertion = AuthenticationAssertion(False, "not-probed", detail)
        if detection.available:
            state = ReadinessState.DETECTED
            state = ReadinessState.CONFIGURED
            assertion = self._authenticate(configuration, detection)
            checks["authenticated"] = assertion.authenticated
            detail = assertion.detail
            if assertion.authenticated:
                state = ReadinessState.AUTHENTICATED
                checks["healthy"] = True
                state = ReadinessState.HEALTHY
                checks["registered"] = True
                state = ReadinessState.REGISTERED
                checks["available"] = True
                state = ReadinessState.AVAILABLE
        auth_probe_sha256 = _sha256_json(
            {
                "provider_id": "codex",
                "version": detection.version,
                "authenticated": assertion.authenticated,
                "method": assertion.method,
            }
        )
        readiness = ProviderReadiness(
            "codex",
            state,
            checks,
            detection.executable,
            command,
            detection.version,
            detail,
            auth_probe_sha256,
            _file_sha256(detection.executable),
        )
        certified = self.certified_roles.get("codex", frozenset())
        return ProviderInstance(
            "codex:local",
            configuration,
            readiness,
            CODEX_CAPABILITIES,
            frozenset(role for role in certified if role in configuration.roles),
        )

    def _compose_claude(self, configuration: ProviderConfiguration) -> ProviderInstance:
        detection, command = self._detect_claude(configuration.command)
        checks = {
            "detected": detection.installed,
            "configured": configuration.enabled,
            "supported_version": False,
            "authenticated": False,
            "healthy": False,
            "registered": False,
            "available": False,
        }
        state = ReadinessState.NOT_DETECTED
        detail = detection.detail or "Claude was not detected"
        if detection.installed:
            state = ReadinessState.CONFIGURED
            if _supported_claude_version(detection.version):
                checks["supported_version"] = True
                assertion = self._authenticate_claude(configuration, detection)
                checks["authenticated"] = assertion.authenticated
                detail = assertion.detail
                if assertion.authenticated:
                    state = ReadinessState.AVAILABLE
                    checks.update({"healthy": True, "registered": True, "available": True})
            else:
                detail = (
                    "Claude version is outside the certified range >=2.1.3,<3: "
                    f"{detection.version or 'unknown'}"
                )
                assertion = AuthenticationAssertion(False, "not-probed", detail)
        else:
            assertion = AuthenticationAssertion(False, "not-probed", detail)
        auth_probe_sha256 = _sha256_json(
            {
                "provider_id": "claude",
                "version": detection.version,
                "authenticated": assertion.authenticated,
                "method": assertion.method,
                "supported_version": checks["supported_version"],
            }
        )
        readiness = ProviderReadiness(
            "claude",
            state,
            checks,
            detection.executable,
            command,
            detection.version,
            detail,
            auth_probe_sha256,
            _file_sha256(detection.executable),
        )
        certified = self.certified_roles.get("claude", frozenset())
        return ProviderInstance(
            "claude:local",
            configuration,
            readiness,
            CLAUDE_CAPABILITIES,
            frozenset(role for role in certified if role in configuration.roles),
        )

    def _compose_deepseek(self, configuration: ProviderConfiguration) -> ProviderInstance:
        detection, command = self._detect_deepseek(configuration.command)
        checks = {
            "detected": detection.installed,
            "configured": configuration.enabled,
            "authenticated": False,
            "healthy": False,
            "registered": False,
            "available": False,
            "stable_headless_boundary": detection.stable_headless,
        }
        state = ReadinessState.NOT_DETECTED
        detail = detection.detail or "DeepSeek was not detected"
        assertion = AuthenticationAssertion(False, "not-probed", detail)
        if detection.installed:
            state = ReadinessState.DETECTED
            state = ReadinessState.CONFIGURED
            if detection.stable_headless:
                assertion = self._authenticate_deepseek(configuration, detection)
                checks["authenticated"] = assertion.authenticated
                detail = assertion.detail
                if assertion.authenticated:
                    state = ReadinessState.AUTHENTICATED
                    checks["healthy"] = True
                    state = ReadinessState.HEALTHY
                    checks["registered"] = True
                    state = ReadinessState.REGISTERED
                    checks["available"] = True
                    state = ReadinessState.AVAILABLE
            else:
                detail = (
                    "DeepSeek stable headless structured-output boundary is unavailable; "
                    f"{detection.detail}"
                )
        auth_probe_sha256 = _sha256_json(
            {
                "provider_id": "deepseek",
                "version": detection.version,
                "authenticated": assertion.authenticated,
                "method": assertion.method,
                "stable_headless_boundary": detection.stable_headless,
            }
        )
        readiness = ProviderReadiness(
            "deepseek",
            state,
            checks,
            detection.executable,
            command,
            detection.version,
            detail,
            auth_probe_sha256,
            _file_sha256(detection.executable),
        )
        certified = self.certified_roles.get("deepseek", frozenset())
        return ProviderInstance(
            "deepseek:local",
            configuration,
            readiness,
            detection.capabilities,
            frozenset(role for role in certified if role in configuration.roles),
        )

    def _authenticate(
        self, configuration: ProviderConfiguration, detection: CodexDetection
    ) -> AuthenticationAssertion:
        reference = configuration.credential_reference
        if reference is None or detection.executable is None:
            return AuthenticationAssertion(False, "none", "credential reference is missing")
        resolved = (detection.executable, *configuration.command[1:])
        return self.credential_broker.resolve(reference, resolved)

    def _probe_codex_native_session(
        self, reference: CredentialReference, command: tuple[str, ...]
    ) -> AuthenticationAssertion:
        del reference
        runner = self.runner or self._run
        try:
            completed = runner((*command, "login", "status"))
        except (OSError, subprocess.SubprocessError) as exc:
            return AuthenticationAssertion(
                False,
                "codex-native-session",
                f"authentication probe failed: {type(exc).__name__}",
            )
        authenticated = completed.returncode == 0
        return AuthenticationAssertion(
            authenticated,
            "codex-native-session",
            (
                "native Codex session authenticated"
                if authenticated
                else "native Codex session unavailable"
            ),
        )

    def _authenticate_claude(
        self, configuration: ProviderConfiguration, detection: ClaudeDetection
    ) -> AuthenticationAssertion:
        reference = configuration.credential_reference
        if reference is None or detection.executable is None:
            return AuthenticationAssertion(False, "none", "credential reference is missing")
        resolved = (detection.executable, *configuration.command[1:])
        return self.credential_broker.resolve(reference, resolved)

    def _probe_claude_native_session(
        self, reference: CredentialReference, command: tuple[str, ...]
    ) -> AuthenticationAssertion:
        del reference
        runner = self.runner or self._run
        try:
            completed = runner((*command, "auth", "status"))
        except (OSError, subprocess.SubprocessError) as exc:
            return AuthenticationAssertion(
                False,
                "claude-native-session",
                f"authentication probe failed: {type(exc).__name__}",
            )
        authenticated = False
        if completed.returncode == 0:
            try:
                status = json.loads(completed.stdout)
            except json.JSONDecodeError:
                status = None
            authenticated = isinstance(status, Mapping) and status.get("loggedIn") is True
        return AuthenticationAssertion(
            authenticated,
            "claude-native-session",
            (
                "native Claude session authenticated"
                if authenticated
                else "native Claude session unavailable"
            ),
        )

    def _authenticate_deepseek(
        self, configuration: ProviderConfiguration, detection: DeepSeekDetection
    ) -> AuthenticationAssertion:
        reference = configuration.credential_reference
        if reference is None or detection.executable is None:
            return AuthenticationAssertion(False, "none", "credential reference is missing")
        resolved = (detection.executable,)
        return self.credential_broker.resolve(reference, resolved)

    def _probe_deepseek_native_session(
        self, reference: CredentialReference, command: tuple[str, ...]
    ) -> AuthenticationAssertion:
        del reference
        runner = self.runner or self._run
        try:
            completed = runner((*command, "auth", "status"))
        except (OSError, subprocess.SubprocessError) as exc:
            return AuthenticationAssertion(
                False,
                "deepseek-native-session",
                f"authentication probe failed: {type(exc).__name__}",
            )
        authenticated = False
        if completed.returncode == 0:
            try:
                status = json.loads(completed.stdout)
            except (TypeError, json.JSONDecodeError):
                status = None
            authenticated = (
                isinstance(status, Mapping) and status.get("authenticated") is True
            )
        return AuthenticationAssertion(
            authenticated,
            "deepseek-native-session",
            (
                "native DeepSeek session authenticated"
                if authenticated
                else "native DeepSeek session unavailable"
            ),
        )

    def _detect_codex(
        self, command: tuple[str, ...]
    ) -> tuple[CodexDetection, tuple[str, ...]]:
        resolved = self.which(command[0])
        if resolved is None:
            return (
                CodexDetection(False, None, None, error=f"{command[0]} was not found on PATH"),
                command,
            )
        resolved_command = (resolved, *command[1:])
        runner = self.runner or self._run
        try:
            completed = runner((*resolved_command, "--version"))
        except (OSError, subprocess.SubprocessError) as exc:
            return (
                CodexDetection(
                    False,
                    resolved,
                    None,
                    error=f"Codex version probe failed: {type(exc).__name__}",
                ),
                resolved_command,
            )
        output = (completed.stdout or completed.stderr or "").strip()
        match = _VERSION.search(output)
        if completed.returncode != 0 or match is None:
            reason = (
                f"Codex version probe exited with {completed.returncode}"
                if completed.returncode != 0
                else "Codex version output did not contain a semantic version"
            )
            return (
                CodexDetection(False, resolved, None, raw_version=output, error=reason),
                resolved_command,
            )
        return (
            CodexDetection(True, resolved, match.group(1), raw_version=output),
            resolved_command,
        )

    def _detect_claude(
        self, command: tuple[str, ...]
    ) -> tuple[ClaudeDetection, tuple[str, ...]]:
        resolved = self.which(command[0])
        if resolved is None:
            return ClaudeDetection(False, detail=f"{command[0]} was not found on PATH"), command
        resolved_command = (resolved, *command[1:])
        runner = self.runner or self._run
        try:
            completed = runner((*resolved_command, "--version"))
        except (OSError, subprocess.SubprocessError) as exc:
            return (
                ClaudeDetection(
                    False,
                    resolved,
                    detail=f"Claude version probe failed: {type(exc).__name__}",
                ),
                resolved_command,
            )
        output = (completed.stdout or completed.stderr or "").strip()
        match = _VERSION.search(output)
        if completed.returncode != 0 or match is None:
            reason = (
                f"Claude version probe exited with {completed.returncode}"
                if completed.returncode != 0
                else "Claude version output did not contain a semantic version"
            )
            return ClaudeDetection(False, resolved, detail=reason), resolved_command
        return ClaudeDetection(True, resolved, match.group(1), output), resolved_command

    def _detect_deepseek(
        self, command: tuple[str, ...]
    ) -> tuple[DeepSeekDetection, tuple[str, ...]]:
        if len(command) != 1:
            return (
                DeepSeekDetection(
                    False,
                    detail="configured DeepSeek command cannot pre-supply caller flags",
                ),
                command,
            )
        detection = detect_deepseek(
            command[0],
            which=self.which,
            runner=self.runner,
        )
        resolved_command = (
            (detection.executable,) if detection.executable is not None else command
        )
        return detection, resolved_command

    @staticmethod
    def _run(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )

    @staticmethod
    def _string(value: object, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ProviderSetupError(f"{name} must be a non-empty string")
        return value

    @staticmethod
    def _string_array(value: object, name: str) -> tuple[str, ...]:
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            raise ProviderSetupError(f"{name} must be an array of non-empty strings")
        return tuple(value)


def _supported_claude_version(version: str | None) -> bool:
    if version is None:
        return False
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9.-]+)?", version)
    if match is None:
        return False
    observed = tuple(int(item) for item in match.groups())
    return _CLAUDE_MINIMUM <= observed < _CLAUDE_MAXIMUM_EXCLUSIVE


def _sha256_json(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: str | None) -> str | None:
    if path is None:
        return None
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None
