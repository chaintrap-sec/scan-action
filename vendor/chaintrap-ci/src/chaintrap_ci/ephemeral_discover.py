"""Discover ephemeral npm/PyPI installs from CI scripts and workflows."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from chaintrap_ci.discover import _dedupe_items, _resolve_search_dirs
from chaintrap_ci.ephemeral_shell import extract_specs_from_command, iter_command_lines_from_run_block
from chaintrap_ci.workflow_audit import _iter_run_blocks

_MAX_SHELL_FILES = 50
_SKIP_DIR_PARTS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "vendor",
        "__pycache__",
        ".tox",
        "dist",
        "build",
    }
)

_WORKFLOW_GLOB = (".github", "workflows")
_DOCKERFILE_NAMES = ("Dockerfile",)
_SHELL_SUFFIXES = (".sh", ".mk")
_MAKEFILE_NAMES = ("Makefile", "GNUmakefile", "makefile")


def _should_skip_path(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return bool(parts & _SKIP_DIR_PARTS)


def _iter_workflow_files(root: Path, search_dirs: list[Path]) -> Iterator[Path]:
    for search_dir in search_dirs:
        wf_dir = search_dir / _WORKFLOW_GLOB[0] / _WORKFLOW_GLOB[1]
        if not wf_dir.is_dir():
            continue
        for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
            if path.is_file() and not _should_skip_path(path):
                yield path


def _iter_dockerfiles(root: Path, search_dirs: list[Path]) -> Iterator[Path]:
    count = 0
    for search_dir in search_dirs:
        for path in sorted(search_dir.rglob("Dockerfile*")):
            if not path.is_file() or _should_skip_path(path):
                continue
            if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
                yield path
                count += 1
                if count >= _MAX_SHELL_FILES:
                    return


def _iter_shell_files(root: Path, search_dirs: list[Path]) -> Iterator[Path]:
    count = 0
    for search_dir in search_dirs:
        for path in sorted(search_dir.rglob("*")):
            if not path.is_file() or _should_skip_path(path):
                continue
            if path.name in _MAKEFILE_NAMES or path.suffix in _SHELL_SUFFIXES:
                yield path
                count += 1
                if count >= _MAX_SHELL_FILES:
                    return


def _iter_package_json_scripts(root: Path, search_dirs: list[Path]) -> Iterator[tuple[Path, str, str]]:
    for search_dir in search_dirs:
        for path in sorted(search_dir.rglob("package.json")):
            if not path.is_file() or _should_skip_path(path):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if not isinstance(scripts, dict):
                continue
            for name, cmd in scripts.items():
                if isinstance(cmd, str) and cmd.strip():
                    yield path, str(name), cmd


def _dockerfile_run_lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = re.match(r"^\s*RUN\s+(.+)$", line, re.I)
        if m:
            out.append((i, m.group(1).strip()))
    return out


def _shell_install_lines(text: str) -> list[tuple[int, str]]:
    patterns = (
        r"\bnpx\b",
        r"\bpnpm\s+dlx\b",
        r"\byarn\s+dlx\b",
        r"\bbunx\b",
        r"\bpip3?\s+install\b",
        r"\buvx\b",
        r"\buv\s+(?:pip|tool|x)\b",
        r"\bpipx\s+run\b",
        r"\bpython3?\s+-m\s+pip\s+install\b",
    )
    combined = re.compile("|".join(patterns), re.I)
    out: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if combined.search(line):
            out.append((i, line.strip()))
    return out


def _make_ephemeral_item(
    *,
    eco: str,
    pkg_spec: str,
    rel_file: str,
    line: int,
    kind: str,
    command: str,
    unpinned: bool,
) -> dict[str, Any]:
    return {
        "ecosystem": eco,
        "package_spec": pkg_spec,
        "resolution_source": "ephemeral",
        "ephemeral_source": {
            "file": rel_file,
            "line": line,
            "kind": kind,
            "command": command[:500],
        },
        "ephemeral_unpinned": unpinned,
    }


def discover_ephemeral(
    workspace: Path,
    *,
    paths: list[str] | None = None,
    ecosystems: set[str] | None = None,
    max_items: int = 200,
    candidate_files: set[str] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Scan workflows, package.json scripts, Dockerfiles, and shell files."""
    root = workspace.resolve()
    wanted = ecosystems or {"npm", "pypi"}
    paths_str = ",".join(paths) if paths else "."
    search_dirs = _resolve_search_dirs(root, paths_str)

    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int]] = set()

    def _allowed(rel: str) -> bool:
        if candidate_files is None:
            return True
        return rel in candidate_files

    def _add_from_command(
        command: str,
        *,
        file_path: Path,
        line: int,
        kind: str,
    ) -> None:
        rel = file_path.relative_to(root).as_posix()
        if not _allowed(rel):
            return
        cwd = file_path.parent
        for row in extract_specs_from_command(command, cwd=cwd, ecosystems=wanted):
            pkg_spec = str(row["package_spec"])
            eco = str(row["ecosystem"])
            key = (eco, pkg_spec.lower(), rel, line)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                _make_ephemeral_item(
                    eco=eco,
                    pkg_spec=pkg_spec,
                    rel_file=rel,
                    line=line,
                    kind=kind,
                    command=command,
                    unpinned=bool(row.get("unpinned")),
                )
            )

    for wf_path in _iter_workflow_files(root, search_dirs):
        try:
            text = wf_path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line_no, block in _iter_run_blocks(text):
            for cmd_line in iter_command_lines_from_run_block(block):
                _add_from_command(cmd_line, file_path=wf_path, line=line_no, kind="workflow")

    for pkg_path, script_name, cmd in _iter_package_json_scripts(root, search_dirs):
        rel = pkg_path.relative_to(root).as_posix()
        if not _allowed(rel):
            continue
        _add_from_command(cmd, file_path=pkg_path, line=1, kind="package_json_script")

    docker_count = 0
    for df_path in _iter_dockerfiles(root, search_dirs):
        docker_count += 1
        if docker_count > _MAX_SHELL_FILES:
            break
        try:
            text = df_path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line_no, cmd in _dockerfile_run_lines(text):
            _add_from_command(cmd, file_path=df_path, line=line_no, kind="dockerfile")

    shell_count = 0
    for sh_path in _iter_shell_files(root, search_dirs):
        shell_count += 1
        if shell_count > _MAX_SHELL_FILES:
            break
        try:
            text = sh_path.read_text(encoding="utf-8")
        except OSError:
            continue
        kind = "shell"
        for line_no, cmd in _shell_install_lines(text):
            _add_from_command(cmd, file_path=sh_path, line=line_no, kind=kind)

    deduped = _dedupe_items(items)
    if max_items > 0:
        deduped = deduped[:max_items]
    mode = "ephemeral-full" if candidate_files is None else "ephemeral-diff"
    return deduped, mode


def lockfile_spec_keys(lockfile_items: list[dict[str, Any]]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for row in lockfile_items:
        eco = str(row.get("ecosystem") or "").lower()
        spec = str(row.get("package_spec") or "").lower()
        if eco and spec:
            keys.add((eco, spec))
            name = spec.rsplit("@", 1)[0] if "@" in spec else spec
            keys.add((eco, f"{name}@unknown"))
    return keys


def hide_ephemeral_in_lockfile(
    ephemeral: list[dict[str, Any]],
    lockfile_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    locked = lockfile_spec_keys(lockfile_items)
    out: list[dict[str, Any]] = []
    for row in ephemeral:
        eco = str(row.get("ecosystem") or "").lower()
        spec = str(row.get("package_spec") or "").lower()
        if (eco, spec) in locked:
            continue
        name = spec.rsplit("@", 1)[0] if "@" in spec else spec
        if (eco, f"{name}@unknown") in locked and spec.endswith("@unknown"):
            continue
        out.append(row)
    return out
