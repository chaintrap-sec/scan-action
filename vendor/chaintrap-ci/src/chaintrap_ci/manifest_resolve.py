"""Compile unpinned manifests (requirements.txt, package.json) to exact pins on the runner."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

_COMPILE_TIMEOUT_SEC = 120
_REQ_PINNED = re.compile(
    r"^([a-zA-Z0-9][\w.\-]*(?:\[[^\]]+\])?)\s*==\s*([^\s;#]+)",
    re.MULTILINE,
)
_REQ_LINE = re.compile(
    r"^\s*([a-zA-Z0-9][\w.\-]*(?:\[[^\]]+\])?)\s*(.*)$",
)
_SKIP_REQ_PREFIXES = ("-r", "--requirement", "-c", "--constraint", "-e", "--editable")

_PYPI_LOCKFILE_NAMES = frozenset(
    {"uv.lock", "poetry.lock", "Pipfile.lock", "constraints.txt"}
)
_NPM_LOCKFILE_NAMES = frozenset(
    {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}
)


@dataclass
class CompileResult:
    packages: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    duration_ms: int | None = None
    tool: str | None = None


def _package_spec(name: str, version: str) -> str:
    return f"{name}@{version}"


def _strip_extras(name: str) -> str:
    bracket = name.find("[")
    if bracket >= 0:
        return name[:bracket]
    return name


def parse_compiled_requirements_text(
    text: str,
    *,
    manifest_path: str = "",
    resolution_source: str = "compile",
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in _REQ_PINNED.finditer(text):
        name = _strip_extras(match.group(1).strip())
        version = match.group(2).strip()
        if not name or not version:
            continue
        out.append(
            {
                "ecosystem": "pypi",
                "package_spec": _package_spec(name, version),
                "lockfile_path": manifest_path or None,
                "resolution_source": resolution_source,
            }
        )
    return out


def requirements_has_unpinned_lines(text: str) -> bool:
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(_SKIP_REQ_PREFIXES):
            continue
        if "==" in line:
            continue
        if re.match(r"^[a-zA-Z0-9]", line):
            return True
    return False


def _declared_constraints_map(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith(_SKIP_REQ_PREFIXES):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = _strip_extras(m.group(1).strip())
        rest = (m.group(2) or "").strip()
        if name:
            out[name.lower()] = f"{name}{rest}".strip() if rest else name
    return out


def _attach_declared_constraints(
    packages: list[dict[str, Any]], manifest_text: str
) -> list[dict[str, Any]]:
    declared = _declared_constraints_map(manifest_text)
    out: list[dict[str, Any]] = []
    for pkg in packages:
        row = dict(pkg)
        spec = str(row.get("package_spec") or "")
        name = spec.rsplit("@", 1)[0] if "@" in spec else spec
        if name.lower() in declared:
            row["declared_constraint"] = declared[name.lower()]
        out.append(row)
    return out


def _run_compile(cmd: list[str], *, cwd: Path | None = None) -> tuple[str | None, str]:
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
            timeout=_COMPILE_TIMEOUT_SEC,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "compile failed").strip()
        return None, err[:2000]
    return result.stdout, ""


def _uv_available() -> bool:
    return shutil.which("uv") is not None


def _pip_compile_available() -> bool:
    return shutil.which("pip-compile") is not None


def compile_requirements_path(
    req_path: Path,
    *,
    manifest_rel: str = "",
    runner: Callable[..., tuple[str | None, str]] | None = None,
) -> CompileResult:
    """Compile requirements.txt to pinned lines via uv or pip-compile."""
    if not req_path.is_file():
        return CompileResult(error=f"file not found: {req_path}")
    try:
        manifest_text = req_path.read_text(encoding="utf-8")
    except OSError as exc:
        return CompileResult(error=str(exc))

    if runner is not None:
        compiled, err = runner(req_path)
        if err:
            return CompileResult(error=err)
        if compiled is None:
            return CompileResult(error="compile returned no output")
        packages = parse_compiled_requirements_text(
            compiled,
            manifest_path=manifest_rel or req_path.as_posix(),
        )
        return CompileResult(
            packages=_attach_declared_constraints(packages, manifest_text),
            tool="mock",
        )

    with tempfile.TemporaryDirectory(prefix="chaintrap_compile_") as td:
        out_path = Path(td) / "compiled.txt"
        if _uv_available():
            compiled, err = _run_compile(
                ["uv", "pip", "compile", str(req_path), "-o", str(out_path), "--quiet"],
            )
            tool = "uv"
            if not err and out_path.is_file():
                compiled = out_path.read_text(encoding="utf-8")
        elif _pip_compile_available():
            compiled, err = _run_compile(
                ["pip-compile", "--output-file", str(out_path), str(req_path)],
            )
            tool = "pip-compile"
            if not err and out_path.is_file():
                compiled = out_path.read_text(encoding="utf-8")
        else:
            return CompileResult(
                error="uv or pip-compile required to resolve unpinned requirements.txt"
            )

        if err:
            return CompileResult(error=err, tool=tool)
        if not compiled:
            return CompileResult(error="compile produced empty output", tool=tool)

        packages = parse_compiled_requirements_text(
            compiled,
            manifest_path=manifest_rel or req_path.as_posix(),
        )
        return CompileResult(
            packages=_attach_declared_constraints(packages, manifest_text),
            tool=tool,
        )


def compile_requirements_text(
    text: str,
    *,
    manifest_rel: str = "",
    runner: Callable[..., tuple[str | None, str]] | None = None,
) -> CompileResult:
    with tempfile.TemporaryDirectory(prefix="chaintrap_req_") as td:
        req_path = Path(td) / "requirements.txt"
        req_path.write_text(text, encoding="utf-8")
        return compile_requirements_path(
            req_path,
            manifest_rel=manifest_rel,
            runner=runner,
        )


def compile_package_json_path(
    pkg_path: Path,
    *,
    manifest_rel: str = "",
    runner: Callable[[Path], tuple[str | None, str]] | None = None,
) -> CompileResult:
    """Generate package-lock.json without install and parse pinned versions."""
    if not pkg_path.is_file():
        return CompileResult(error=f"file not found: {pkg_path}")

    with tempfile.TemporaryDirectory(prefix="chaintrap_npm_") as td:
        work = Path(td)
        target = work / "package.json"
        target.write_text(pkg_path.read_text(encoding="utf-8"), encoding="utf-8")

        if runner is not None:
            lock_text, err = runner(work)
            if err:
                return CompileResult(error=err)
            if not lock_text:
                return CompileResult(error="npm lockfile generation returned no output")
        else:
            npm = shutil.which("npm")
            if not npm:
                return CompileResult(error="npm CLI required to resolve package.json ranges")
            try:
                result = subprocess.run(
                    [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit"],
                    cwd=str(work),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=_COMPILE_TIMEOUT_SEC,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return CompileResult(error=str(exc))
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "npm failed").strip()
                return CompileResult(error=err[:2000])
            lock_path = work / "package-lock.json"
            if not lock_path.is_file():
                return CompileResult(error="npm did not produce package-lock.json")
            lock_text = lock_path.read_text(encoding="utf-8")

        from chaintrap_ci.discover import _read_package_lock

        lock_tmp = work / "package-lock.json"
        if runner is None:
            lock_tmp = work / "package-lock.json"
        else:
            lock_tmp.write_text(lock_text, encoding="utf-8")

        packages = _read_package_lock(lock_tmp)
        rel = manifest_rel or pkg_path.as_posix()
        for row in packages:
            row["lockfile_path"] = rel
            row["resolution_source"] = "compile"
        return CompileResult(packages=packages, tool="npm")


def dir_has_pypi_lockfile(directory: Path) -> bool:
    for name in _PYPI_LOCKFILE_NAMES:
        if (directory / name).is_file():
            return True
    return False


def dir_has_npm_lockfile(directory: Path) -> bool:
    for name in _NPM_LOCKFILE_NAMES:
        if (directory / name).is_file():
            return True
    return False


def packages_from_requirements_manifest(
    req_path: Path,
    *,
    resolve_manifests: bool,
    manifest_rel: str = "",
    runner: Callable[..., tuple[str | None, str]] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Return packages from == pins and/or compile when unpinned lines exist."""
    try:
        text = req_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], str(exc)

    rel = manifest_rel or req_path.as_posix()
    if not requirements_has_unpinned_lines(text):
        from chaintrap_ci.discover import _read_requirements_txt

        rows = _read_requirements_txt(req_path)
        for row in rows:
            row["lockfile_path"] = rel
            row.setdefault("resolution_source", "lockfile")
        return rows, None

    if not resolve_manifests:
        from chaintrap_ci.discover import _read_requirements_txt

        rows = _read_requirements_txt(req_path)
        for row in rows:
            row["lockfile_path"] = rel
            row.setdefault("resolution_source", "lockfile")
        return rows, None

    if dir_has_pypi_lockfile(req_path.parent):
        return [], "unpinned requirements.txt skipped (uv.lock/poetry.lock present)"

    result = compile_requirements_path(req_path, manifest_rel=rel, runner=runner)
    if result.error:
        return [], result.error
    return result.packages, None


def packages_from_requirements_text(
    text: str,
    *,
    resolve_manifests: bool,
    manifest_rel: str = "",
    runner: Callable[..., tuple[str | None, str]] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    if not requirements_has_unpinned_lines(text):
        rows = parse_compiled_requirements_text(text, manifest_path=manifest_rel)
        for row in rows:
            row.setdefault("resolution_source", "lockfile")
        return rows, None
    if not resolve_manifests:
        rows = parse_compiled_requirements_text(text, manifest_path=manifest_rel)
        for row in rows:
            row.setdefault("resolution_source", "lockfile")
        return rows, None
    result = compile_requirements_text(text, manifest_rel=manifest_rel, runner=runner)
    if result.error:
        return [], result.error
    return result.packages, None
