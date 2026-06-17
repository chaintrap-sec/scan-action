from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from chaintrap_guard.config import default_config_dir


def _shim_dir() -> Path:
    return (default_config_dir() / "shims").resolve()


def _is_guard_shim_path(path: str) -> bool:
    try:
        return Path(path).resolve().parent == _shim_dir()
    except OSError:
        return False


def _pm_candidate_names(name: str) -> list[str]:
    """Windows Node installers ship extensionless bash stubs; prefer .cmd/.exe."""
    if os.name != "nt":
        return [name]
    return [f"{name}.cmd", f"{name}.exe", f"{name}.bat", name]


def _is_runnable_pm_on_windows(path: str) -> bool:
    """Skip extensionless bash/npm stubs that Win32 cannot execute directly."""
    lower = path.lower()
    if lower.endswith((".cmd", ".bat", ".exe", ".com")):
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(2)
    except OSError:
        return False
    # PE executable
    return head == b"MZ"


def find_executable(name: str) -> str | None:
    """Prefer real binary, not chaintrap-guard shims on PATH."""
    guard_names = {"chaintrap-guard", "chaintrap-guard.cmd", "chaintrap-guard.exe"}
    names = _pm_candidate_names(name)
    for candidate_name in names:
        path = os.environ.get("PATH") or ""
        for directory in path.split(os.pathsep):
            candidate = os.path.join(directory, candidate_name)
            if not os.path.isfile(candidate):
                continue
            base = os.path.basename(candidate).lower()
            if base in guard_names or _is_guard_shim_path(candidate):
                continue
            if os.name == "nt" and not _is_runnable_pm_on_windows(candidate):
                continue
            return candidate
        found = shutil.which(candidate_name)
        if (
            found
            and os.path.basename(found).lower() not in guard_names
            and not _is_guard_shim_path(found)
            and (os.name != "nt" or _is_runnable_pm_on_windows(found))
        ):
            return found
    return None


def run_package_manager(manager: str, argv: list[str]) -> int:
    """Execute the real package manager with inherited stdio."""
    exe = find_executable(manager)
    if not exe:
        print(f"chaintrap-guard: could not find '{manager}' on PATH", file=sys.stderr)
        return 127
    try:
        if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
            cmdline = subprocess.list2cmdline([exe, *argv])
            proc = subprocess.run(cmdline, shell=True, check=False)
        else:
            proc = subprocess.run([exe, *argv], check=False)
        return int(proc.returncode)
    except OSError as exc:
        print(f"chaintrap-guard: failed to run {manager}: {exc}", file=sys.stderr)
        return 126
