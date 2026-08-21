# ARTIFEX native distribution

`build.py` creates the V1 reference PyInstaller one-directory bundle and a
strict provenance manifest. The bundle contains Python and all runtime
dependencies: the user does not install Python, pip, or a virtual environment.

Build and smoke the native artifact on the target operating system:

```text
uv run python packaging/build.py --clean --smoke
```

The CI `native-package` matrix repeats this build and smoke test on Windows,
Linux, and macOS, then uploads the entire platform-specific bundle (executable,
bundled libraries, and manifest).
Installation is intentionally two-step: first obtain the explicit effects and
confirmation token, then rerun with that token. The embedded lifecycle manager
writes an exact authenticated file inventory, upgrades transactionally through
a backup, and uninstalls only checksum-verified manifest-owned files. Neither
installer edits PATH nor any
Hermes, Codex, or Claude configuration.
