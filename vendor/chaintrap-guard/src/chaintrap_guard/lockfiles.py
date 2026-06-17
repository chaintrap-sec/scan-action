"""Extract pinned package specs from lockfiles (npm package-lock, uv.lock)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from chaintrap_guard.models import PackageSpec

_UV_PKG_NAME = re.compile(r'^name\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_UV_PKG_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)


def _dedupe_specs(specs: list[PackageSpec]) -> list[PackageSpec]:
    seen: set[tuple[str, str, str]] = set()
    out: list[PackageSpec] = []
    for s in specs:
        key = (s.ecosystem, s.name.lower(), s.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _npm_name_from_lock_path(path_key: str) -> str | None:
    """node_modules/foo or node_modules/@scope/pkg -> package name."""
    p = (path_key or "").strip()
    if not p.startswith("node_modules/"):
        return None
    rest = p[len("node_modules/") :]
    if not rest or rest == "":
        return None
    if rest.startswith("@"):
        parts = rest.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None
    return rest.split("/")[0]


def read_package_lock(root: Path | None) -> list[PackageSpec]:
    root = root or Path.cwd()
    lock_path = root / "package-lock.json"
    if not lock_path.is_file():
        return []
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    out: list[PackageSpec] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path_key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if path_key == "":
                continue
            ver = str(meta.get("version") or "").strip()
            name = _npm_name_from_lock_path(path_key)
            if name and ver:
                out.append(PackageSpec(name=name, version=ver, ecosystem="npm"))
        return _dedupe_specs(out)

    deps = data.get("dependencies")
    if isinstance(deps, dict):

        def walk(name: str, node: dict) -> None:
            if not isinstance(node, dict):
                return
            ver = str(node.get("version") or "").strip()
            if name and ver:
                out.append(PackageSpec(name=name, version=ver, ecosystem="npm"))
            nested = node.get("dependencies") or {}
            if isinstance(nested, dict):
                for child_name, child_node in nested.items():
                    walk(child_name, child_node)

        for pkg_name, node in deps.items():
            walk(pkg_name, node)
    return _dedupe_specs(out)


def read_uv_lock(root: Path | None) -> list[PackageSpec]:
    root = root or Path.cwd()
    lock_path = root / "uv.lock"
    if not lock_path.is_file():
        return []
    try:
        text = lock_path.read_text(encoding="utf-8")
    except OSError:
        return []

    blocks = re.split(r"\n\[\[package\]\]\n", text)
    out: list[PackageSpec] = []
    for block in blocks:
        if "name" not in block:
            continue
        nm = _UV_PKG_NAME.search(block)
        ver = _UV_PKG_VERSION.search(block)
        if nm and ver:
            out.append(
                PackageSpec(
                    name=nm.group(1).strip(),
                    version=ver.group(1).strip(),
                    ecosystem="pypi",
                )
            )
    return _dedupe_specs(out)


def read_project_pypi_lockfiles(root: Path | None) -> list[PackageSpec]:
    """uv.lock in project root when pip/uv install has no explicit targets."""
    return read_uv_lock(root)
