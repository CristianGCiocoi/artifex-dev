# ARTIFEX native distribution

`build.py` preserves the V1 reference PyInstaller one-directory build for
historical and non-Windows release compatibility.

`build_windows_installer.py` is the ARTIFEX 2.0 Core Windows shipping path. It
creates a Nuitka standalone distribution and wraps it in the beginner-facing
NSIS `ARTIFEX-Setup.exe`. It does not use Nuitka onefile. The installer copies
the provenance-bound bundle into `C:\Program Files\ARTIFEX`, initializes local
state, and registers and starts the existing per-user managed-service contract.
The user does not install Python, pip, a virtual environment, Nuitka, or NSIS.

The Windows executable uses Nuitka console mode `hide`: direct CLI and MCP
calls reuse an existing terminal with normal standard-stream synchronization,
while a console created for a Start Menu dashboard launch or Task Scheduler
service activation is hidden instead of remaining on screen. Windows may show
a brief console flash while that newly created window is hidden; clean-machine
qualification measures that bounded OS behavior. The ARTIFEX icon is embedded
in the native executable and NSIS installer and is reused by installed
shortcuts and Add/Remove Programs metadata.

Build and smoke the native artifact on the target operating system:

```text
uv run python packaging/build.py --clean --smoke
uv run --python 3.12 python packaging/build_windows_installer.py --clean --smoke
```

The CI `native-package` matrix repeats this build and smoke test on Windows,
Linux, and macOS, then uploads the entire platform-specific bundle (executable,
bundled libraries, and manifest).
Installation is intentionally two-step: first obtain the explicit effects and
confirmation token, then rerun with that token. The embedded lifecycle manager
writes an exact authenticated file inventory, upgrades transactionally through
a backup, and uninstalls only checksum-verified manifest-owned files. Neither
installer edits PATH nor any Hermes, Codex, or Claude configuration. Provider
authentication remains a separate user-owned setup flow.
