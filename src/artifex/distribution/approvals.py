"""Persisted, single-use approvals bound to an exact risk plan."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from artifex.distribution.models import DecisionExplanation, RiskLevel

DEFAULT_APPROVAL_TTL_SECONDS = 600


def user_state_root() -> Path:
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "ARTIFEX"
    if os.environ.get("XDG_STATE_HOME"):
        return Path(os.environ["XDG_STATE_HOME"]) / "artifex"
    return Path.home() / ".artifex"


@dataclass(frozen=True, slots=True)
class ApprovalStore:
    root: Path

    @classmethod
    def default(cls) -> ApprovalStore:
        return cls(user_state_root() / "approvals")

    def issue(
        self,
        plan_fingerprint: str,
        *,
        now: datetime | None = None,
        ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
    ) -> tuple[str, str]:
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("approval TTL must be between 1 and 3600 seconds")
        issued_at = _as_utc(now or datetime.now(UTC))
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        self._ensure_root()
        for _ in range(4):
            token = f"approve-{secrets.token_urlsafe(32)}"
            path = self._record_path(token)
            value = {
                "schema_version": "1.0",
                "plan_fingerprint": plan_fingerprint,
                "issued_at": issued_at.isoformat(),
                "expires_at": expires_at.isoformat(),
            }
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            return token, expires_at.isoformat()
        raise RuntimeError("could not allocate a unique approval challenge")

    def consume(
        self,
        token: str | None,
        expected_plan_fingerprint: str,
        *,
        now: datetime | None = None,
    ) -> None:
        if not isinstance(token, str) or not token.startswith("approve-"):
            raise PermissionError("a valid explicit approval token is required")
        path = self._record_path(token)
        claim = path.with_suffix(f".claimed-{os.getpid()}-{uuid.uuid4().hex}")
        try:
            os.replace(path, claim)
        except FileNotFoundError as exc:
            raise PermissionError(
                "approval token is unknown, expired, or already consumed"
            ) from exc
        try:
            try:
                value = json.loads(claim.read_text(encoding="utf-8"))
                observed = str(value["plan_fingerprint"])
                expires_at = datetime.fromisoformat(str(value["expires_at"]))
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PermissionError("approval token record is invalid") from exc
            if not hmac.compare_digest(observed, expected_plan_fingerprint):
                raise PermissionError("approval token is bound to a different operation or plan")
            if _as_utc(now or datetime.now(UTC)) > _as_utc(expires_at):
                raise PermissionError("approval token has expired")
        finally:
            claim.unlink(missing_ok=True)

    def _record_path(self, token: str) -> Path:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return self.root / f"{digest}.json"

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            self.root.chmod(0o700)


def plan_fingerprint(
    action: str,
    risk: RiskLevel | str,
    *,
    effects: tuple[str, ...],
    rollback: str,
    binding: Mapping[str, Any] | None = None,
) -> str:
    level = RiskLevel(risk)
    value = {
        "action": action,
        "risk": level.value,
        "effects": list(effects),
        "rollback": rollback,
        "binding": dict(binding or {}),
    }
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def issue_decision(
    action: str,
    risk: RiskLevel | str,
    *,
    effects: tuple[str, ...],
    rollback: str,
    binding: Mapping[str, Any] | None = None,
    approval_store: ApprovalStore | None = None,
    issue_token: bool = True,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
) -> DecisionExplanation:
    if not action.strip() or not effects or not rollback.strip():
        raise ValueError("action, effects, and rollback are required")
    level = RiskLevel(risk)
    approval = level is not RiskLevel.READ_ONLY
    fingerprint = plan_fingerprint(
        action, level, effects=effects, rollback=rollback, binding=binding
    )
    token: str | None = None
    expires_at: str | None = None
    if approval and issue_token:
        token, expires_at = (approval_store or ApprovalStore.default()).issue(
            fingerprint, now=now, ttl_seconds=ttl_seconds
        )
    return DecisionExplanation(
        action,
        level,
        effects,
        rollback,
        approval,
        token,
        fingerprint,
        expires_at,
    )


def consume_decision(
    decision: DecisionExplanation,
    supplied_token: str | None,
    *,
    approval_store: ApprovalStore | None = None,
    now: datetime | None = None,
) -> None:
    if not decision.approval_required:
        return
    (approval_store or ApprovalStore.default()).consume(
        supplied_token, decision.plan_fingerprint, now=now
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
