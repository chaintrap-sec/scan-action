"""Discover pinned package specs from lockfiles under a repository root."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_DEFAULT_MAX_ITEMS = 80

_LOCKFILE_NAMES: dict[str, str] = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "npm",
    "yarn.lock": "npm",
    "bun.lock": "npm",
    "uv.lock": "pypi",
    "requirements.txt": "pypi",
    "poetry.lock": "pypi",
    "Pipfile.lock": "pypi",
}

_UV_PKG_NAME = re.compile(r'^name\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_UV_PKG_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_POETRY_PKG_NAME = re.compile(r'^name\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_POETRY_PKG_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_REQ_PINNED = re.compile(
    r"^([a-zA-Z0-9][\w.\-]*(?:\[[^\]]+\])?)\s*==\s*([^\s;#]+)",
    re.MULTILINE,
)
_PNPM_SLASH_SCOPED = re.compile(
    r"^\s*/(@[^/]+/[^/]+)/([\d][\w.\-+]*)\s*:",
    re.MULTILINE,
)
_PNPM_SLASH_PLAIN = re.compile(
    r"^\s*/([^/@\s][^/]*)/([\d][\w.\-+]*)\s*:",
    re.MULTILINE,
)
_PNPM_AT_KEY = re.compile(
    r"^\s*['\"]?(@?[^@\s'\"/]+(?:/[^@\s'\"/]+)?)@([\d][\w.\-+]*)['\"]?\s*:",
    re.MULTILINE,
)
_YARN_CLASSIC = re.compile(
    r"^(\S+?)@([\d][\w.\-+]*(?:\.[\w.\-+]+)*):\s*$",
    re.MULTILINE,
)
_YARN_BERRY = re.compile(
    r'^\s*"(@?[^@\s"]+@?[^@\s"]*)@npm:([^"]+)":\s*$',
    re.MULTILINE,
)
_BUN_PKG = re.compile(
    r'^\s*"(@?[^"]+)":\s*\[\s*"([^"]+)"',
    re.MULTILINE,
)


def _package_spec(name: str, version: str) -> str:
    return f"{name}@{version}"


def _dedupe_items(items: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for item in items:
        eco = str(item.get("ecosystem") or "")
        spec = str(item.get("package_spec") or "")
        key = (eco, spec.lower())
        if not eco or not spec or key in seen:
            continue
        seen.add(key)
        out.append({"ecosystem": eco, "package_spec": spec})
    return out


def _npm_name_from_lock_path(path_key: str) -> str | None:
    """node_modules/foo or node_modules/@scope/pkg -> package name."""
    p = (path_key or "").strip()
    if not p.startswith("node_modules/"):
        return None
    rest = p[len("node_modules/") :]
    if not rest:
        return None
    if rest.startswith("@"):
        parts = rest.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None
    return rest.split("/")[0]


def _read_package_lock(lock_path: Path) -> list[dict]:
    if not lock_path.is_file():
        return []
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    out: list[dict] = []
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
                out.append(
                    {
                        "ecosystem": "npm",
                        "package_spec": _package_spec(name, ver),
                    }
                )
        return out

    deps = data.get("dependencies")
    if isinstance(deps, dict):

        def walk(name: str, node: dict[str, Any]) -> None:
            if not isinstance(node, dict):
                return
            ver = str(node.get("version") or "").strip()
            if name and ver:
                out.append(
                    {
                        "ecosystem": "npm",
                        "package_spec": _package_spec(name, ver),
                    }
                )
            nested = node.get("dependencies") or {}
            if isinstance(nested, dict):
                for child_name, child_node in nested.items():
                    walk(child_name, child_node)

        for pkg_name, node in deps.items():
            walk(pkg_name, node)
    return out


def _read_uv_lock(lock_path: Path) -> list[dict]:
    if not lock_path.is_file():
        return []
    try:
        text = lock_path.read_text(encoding="utf-8")
    except OSError:
        return []

    blocks = re.split(r"\n\[\[package\]\]\n", text)
    out: list[dict] = []
    for block in blocks:
        if "name" not in block:
            continue
        nm = _UV_PKG_NAME.search(block)
        ver = _UV_PKG_VERSION.search(block)
        if nm and ver:
            out.append(
                {
                    "ecosystem": "pypi",
                    "package_spec": _package_spec(
                        nm.group(1).strip(),
                        ver.group(1).strip(),
                    ),
                }
            )
    return out


def _read_poetry_lock(lock_path: Path) -> list[dict]:
    if not lock_path.is_file():
        return []
    try:
        text = lock_path.read_text(encoding="utf-8")
    except OSError:
        return []

    blocks = re.split(r"\n\[\[package\]\]\n", text)
    out: list[dict] = []
    for block in blocks:
        if "name" not in block:
            continue
        nm = _POETRY_PKG_NAME.search(block)
        ver = _POETRY_PKG_VERSION.search(block)
        if nm and ver:
            out.append(
                {
                    "ecosystem": "pypi",
                    "package_spec": _package_spec(
                        nm.group(1).strip(),
                        ver.group(1).strip(),
                    ),
                }
            )
    return out


def _strip_extras(name: str) -> str:
    bracket = name.find("[")
    if bracket >= 0:
        return name[:bracket]
    return name


def _read_requirements_txt(lock_path: Path) -> list[dict]:
    if not lock_path.is_file():
        return []
    try:
        text = lock_path.read_text(encoding="utf-8")
    except OSError:
        return []

    out: list[dict] = []
    for match in _REQ_PINNED.finditer(text):
        name = _strip_extras(match.group(1).strip())
        version = match.group(2).strip()
        if name and version:
            out.append(
                {
                    "ecosystem": "pypi",
                    "package_spec": _package_spec(name, version),
                }
            )
    return out


def _read_yarn_lock(lock_path: Path) -> list[dict]:
    if not lock_path.is_file():
        return []
    try:
        text = lock_path.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[dict] = []
    for pattern in (_YARN_BERRY, _YARN_CLASSIC):
        for match in pattern.finditer(text):
            name = match.group(1).strip()
            version = match.group(2).strip()
            if name and version:
                out.append(
                    {
                        "ecosystem": "npm",
                        "package_spec": _package_spec(name, version),
                    }
                )
    return out


def _read_bun_lock(lock_path: Path) -> list[dict]:
    if not lock_path.is_file():
        return []
    try:
        text = lock_path.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[dict] = []
    for match in _BUN_PKG.finditer(text):
        name = match.group(1).strip()
        version = match.group(2).strip()
        if name and version:
            out.append(
                {
                    "ecosystem": "npm",
                    "package_spec": _package_spec(name, version),
                }
            )
    return out


def _read_pipfile_lock(lock_path: Path) -> list[dict]:
    if not lock_path.is_file():
        return []
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[dict] = []
    for section in ("default", "develop"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, meta in block.items():
            if not isinstance(meta, dict):
                continue
            ver = str(meta.get("version") or "").strip().lstrip("==")
            if name and ver:
                out.append(
                    {
                        "ecosystem": "pypi",
                        "package_spec": _package_spec(name, ver),
                    }
                )
    return out


def _read_pnpm_lock(lock_path: Path) -> list[dict]:
    if not lock_path.is_file():
        return []
    try:
        text = lock_path.read_text(encoding="utf-8")
    except OSError:
        return []

    marker = re.search(r"^packages:\s*$", text, re.MULTILINE)
    if not marker:
        return []

    section = text[marker.end() :]
    out: list[dict] = []
    for pattern in (_PNPM_AT_KEY, _PNPM_SLASH_SCOPED, _PNPM_SLASH_PLAIN):
        for match in pattern.finditer(section):
            name = match.group(1).strip()
            version = match.group(2).strip()
            if name and version:
                out.append(
                    {
                        "ecosystem": "npm",
                        "package_spec": _package_spec(name, version),
                    }
                )
    return out


_READERS = {
    "package-lock.json": _read_package_lock,
    "pnpm-lock.yaml": _read_pnpm_lock,
    "yarn.lock": _read_yarn_lock,
    "bun.lock": _read_bun_lock,
    "uv.lock": _read_uv_lock,
    "requirements.txt": _read_requirements_txt,
    "poetry.lock": _read_poetry_lock,
    "Pipfile.lock": _read_pipfile_lock,
}


def _resolve_search_dirs(root: Path, paths: str) -> list[Path]:
    root = root.resolve()
    raw = (paths or ".").strip()
    if raw == ".":
        return [root]

    dirs: list[Path] = []
    for part in raw.split(","):
        part = part.strip().strip("/\\")
        if not part:
            continue
        candidate = (root / part).resolve()
        if candidate.is_dir():
            dirs.append(candidate)
    return dirs or [root]


def _iter_lockfiles(search_dir: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(search_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in _LOCKFILE_NAMES:
            found.append(path)
    return found


def _parse_lockfile(lock_path: Path) -> list[dict]:
    reader = _READERS.get(lock_path.name)
    if reader is None:
        return []
    return reader(lock_path)


def discover_packages(
    root: Path,
    ecosystems: set[str],
    *,
    paths: str = ".",
    max_items: int = _DEFAULT_MAX_ITEMS,
) -> list[dict]:
    """Walk lockfiles under root and return pinned package specs.

    Each item has keys ``ecosystem`` (``npm`` or ``pypi``) and ``package_spec``
    (``name@version``). Results are deduplicated and capped at ``max_items``.
    """
    wanted = {e.strip().lower() for e in ecosystems if e and e.strip()}
    if not wanted:
        wanted = {"npm", "pypi"}

    collected: list[dict] = []
    for search_dir in _resolve_search_dirs(root, paths):
        for lock_path in _iter_lockfiles(search_dir):
            eco = _LOCKFILE_NAMES.get(lock_path.name)
            if not eco or eco not in wanted:
                continue
            collected.extend(_parse_lockfile(lock_path))

    deduped = _dedupe_items(collected)
    if max_items > 0:
        return deduped[:max_items]
    return deduped


def discover(
    workspace: Path | str,
    *,
    paths: list[str] | None = None,
    ecosystems: list[str] | None = None,
    max_packages: int = _DEFAULT_MAX_ITEMS,
) -> list[dict]:
    """GHA-friendly wrapper around discover_packages."""
    root = Path(workspace)
    paths_str = ",".join(paths) if paths else "."
    eco_set = {e.strip().lower() for e in (ecosystems or ["npm", "pypi"]) if e.strip()}
    return discover_packages(root, eco_set, paths=paths_str, max_items=max_packages)
