"""Diff-aware lockfile discovery for pull_request events."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from chaintrap_ci.discover import _LOCKFILE_NAMES, _dedupe_items, _parse_lockfile, _iter_lockfiles


def _git_show_file(repo_root: Path, ref: str, rel_path: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{rel_path}"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None


def _parse_lockfile_text(lock_name: str, text: str) -> list[dict]:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=lock_name, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(text)
        tmp_path = Path(tmp.name)
    try:
        return _parse_lockfile(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _packages_from_lockfile_at_ref(
    repo_root: Path, ref: str, lock_path: Path
) -> set[tuple[str, str]]:
    rel = lock_path.relative_to(repo_root).as_posix()
    text = _git_show_file(repo_root, ref, rel)
    if text is None:
        return set()
    rows = _parse_lockfile_text(lock_path.name, text)
    return {
        (str(r.get("ecosystem") or ""), str(r.get("package_spec") or ""))
        for r in rows
        if r.get("ecosystem") and r.get("package_spec")
    }


def discover_added_packages(
    workspace: Path,
    *,
    base_ref: str,
    head_ref: str = "HEAD",
    ecosystems: set[str] | None = None,
    paths: list[str] | None = None,
    max_items: int = 200,
) -> tuple[list[dict], str]:
    """Return packages present in head lockfiles but not in base (PR delta)."""
    root = workspace.resolve()
    wanted = ecosystems or {"npm", "pypi"}

    from chaintrap_ci.discover import _resolve_search_dirs

    search_dirs = _resolve_search_dirs(root, ",".join(paths) if paths else ".")
    head_locks: list[Path] = []
    for search_dir in search_dirs:
        head_locks.extend(_iter_lockfiles(search_dir))

    added: list[dict] = []
    seen: set[tuple[str, str]] = set()
    mode = "diff"

    if not head_locks:
        return [], "no-lockfiles"

    for lock_path in head_locks:
        eco = _LOCKFILE_NAMES.get(lock_path.name)
        if not eco or eco not in wanted:
            continue
        head_rows = _parse_lockfile(lock_path)
        head_set = {
            (str(r.get("ecosystem") or ""), str(r.get("package_spec") or ""))
            for r in head_rows
        }
        base_set = _packages_from_lockfile_at_ref(root, base_ref, lock_path)
        if not base_set and base_ref:
            # New lockfile or base ref unavailable — treat all head pins as added
            delta = head_set
            mode = "diff-new-lockfile"
        else:
            delta = head_set - base_set

        for eco_key, spec in sorted(delta):
            key = (eco_key, spec.lower())
            if key in seen:
                continue
            seen.add(key)
            added.append({"ecosystem": eco_key, "package_spec": spec})

    deduped = _dedupe_items(added)
    if max_items > 0:
        deduped = deduped[:max_items]
    return deduped, mode
