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


def _lockfile_exists_at_ref(repo_root: Path, ref: str, rel_path: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{ref}:{rel_path}"],
            cwd=str(repo_root),
            capture_output=True,
            check=False,
            timeout=30,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _lockfile_changed_between(
    repo_root: Path, base_ref: str, head_ref: str, rel_path: str
) -> bool:
    """True when lockfile content differs between base and head (PR range)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--quiet", f"{base_ref}...{head_ref}", "--", rel_path],
            cwd=str(repo_root),
            capture_output=True,
            check=False,
            timeout=60,
        )
        if result.returncode == 0:
            return False
        if result.returncode == 1:
            return True
    except (OSError, subprocess.TimeoutExpired):
        pass
    return True


def _parse_lockfile_text(lock_name: str, text: str) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="chaintrap_lock_") as td:
        tmp_path = Path(td) / lock_name
        tmp_path.write_text(text, encoding="utf-8")
        return _parse_lockfile(tmp_path)


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
    saw_new_lockfile = False

    if not head_locks:
        return [], "no-lockfiles"

    for lock_path in head_locks:
        eco = _LOCKFILE_NAMES.get(lock_path.name)
        if not eco or eco not in wanted:
            continue

        rel = lock_path.relative_to(root).as_posix()
        if base_ref and not _lockfile_changed_between(root, base_ref, head_ref, rel):
            continue

        head_rows = _parse_lockfile(lock_path)
        head_set = {
            (str(r.get("ecosystem") or ""), str(r.get("package_spec") or ""))
            for r in head_rows
        }

        if base_ref and _lockfile_exists_at_ref(root, base_ref, rel):
            base_set = _packages_from_lockfile_at_ref(root, base_ref, lock_path)
            if not base_set and _git_show_file(root, base_ref, rel) is None:
                continue
            delta = head_set - base_set
        else:
            delta = head_set
            saw_new_lockfile = True

        for eco_key, spec in sorted(delta):
            key = (eco_key, spec.lower())
            if key in seen:
                continue
            seen.add(key)
            added.append(
                {
                    "ecosystem": eco_key,
                    "package_spec": spec,
                    "lockfile": rel,
                }
            )

    if saw_new_lockfile:
        mode = "diff-new-lockfile"

    deduped = _dedupe_items(added)
    if max_items > 0:
        deduped = deduped[:max_items]
    return deduped, mode
