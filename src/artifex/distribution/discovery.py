"""Bounded, read-only discovery of supported tools and local resources."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

from artifex.distribution.models import EnvironmentDiscovery, ResourceEnvelope, ToolDiscovery

SUPPORTED_TOOLS = ("git", "hermes", "codex", "claude")
_VERSION = re.compile(r"(?<!\d)(\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?)")
_MAX_OUTPUT = 512


def detect_resources(path: str | Path = ".") -> ResourceEnvelope:
    target = Path(path).resolve()
    existing = target if target.exists() else target.parent
    memory: int | None = None
    if os.name == "nt":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            # ``ctypes.windll`` intentionally exists only on Windows. Resolve it
            # dynamically so non-Windows type-checking does not assume a
            # platform-specific module attribute while the runtime branch stays
            # guarded by ``os.name == "nt"``.
            windows_dlls = getattr(ctypes, "windll", None)
            if windows_dlls is not None and windows_dlls.kernel32.GlobalMemoryStatusEx(
                ctypes.byref(status)
            ):
                memory = int(status.total_physical)
        except (AttributeError, OSError):
            memory = None
    elif hasattr(os, "sysconf"):
        try:
            memory = int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
        except (OSError, ValueError):
            memory = None
    return ResourceEnvelope(
        logical_cpu_count=max(1, os.cpu_count() or 1),
        memory_bytes=memory,
        disk_free_bytes=shutil.disk_usage(existing).free,
        platform=platform.system() or "Unknown",
        architecture=platform.machine() or "unknown",
    )


def discover_environment(
    *,
    search_path: str | None = None,
    command_overrides: Mapping[str, str | None] | None = None,
    resource_path: str | Path = ".",
    timeout_seconds: float = 5.0,
) -> EnvironmentDiscovery:
    if not 0.1 <= timeout_seconds <= 15:
        raise ValueError("discovery timeout must be between 0.1 and 15 seconds")
    overrides = command_overrides or {}
    tools = tuple(
        _discover_tool(
            tool,
            executable=overrides.get(tool, shutil.which(tool, path=search_path)),
            timeout_seconds=timeout_seconds,
        )
        for tool in SUPPORTED_TOOLS
    )
    return EnvironmentDiscovery(tools, detect_resources(resource_path))


def _discover_tool(tool: str, *, executable: str | None, timeout_seconds: float) -> ToolDiscovery:
    if executable is None:
        return ToolDiscovery(tool, "NOT_FOUND", None, None, f"{tool} was not found on PATH")
    try:
        result = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolDiscovery(tool, "DEGRADED", executable, None, type(exc).__name__)
    output = (result.stdout or result.stderr).strip().replace("\x00", "")[:_MAX_OUTPUT]
    match = _VERSION.search(output)
    status = "PASS" if result.returncode == 0 else "DEGRADED"
    return ToolDiscovery(
        tool,
        status,
        executable,
        match.group(1) if match else None,
        output or f"exited with code {result.returncode}",
    )
