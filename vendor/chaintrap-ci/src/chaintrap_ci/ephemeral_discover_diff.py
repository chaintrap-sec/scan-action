"""Diff-aware ephemeral dependency discovery for pull_request events."""

from __future__ import annotations

import subprocess
from pathlib import Path

from chaintrap_ci.discover_diff import _path_changed_between
from chaintrap_ci.ephemeral_discover import discover_ephemeral

_CHAINTRAP_WORKFLOW_MARKERS = (
    "chaintrap-sec/scan-action",
    "chaintrap.yml",
    ".chaintrap.yml",
)

_EPHEMERAL_CANDIDATE_SUFFIXES = (".yml", ".yaml", ".sh", ".mk")
_EPHEMERAL_CANDIDATE_NAMES = frozenset(
    {"Dockerfile", "Makefile", "GNUmakefile", "makefile", "package.json"}
)


def _git_diff_name_only(repo_root: Path, base_ref: str, head_ref: str) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_ref}...{head_ref}"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if result.returncode not in (0, 1):
            return []
        return [ln.strip().replace("\\", "/") for ln in result.stdout.splitlines() if ln.strip()]
    except (OSError, subprocess.TimeoutExpired):
        return []


def _file_exists_at_ref(repo_root: Path, ref: str, rel_path: str) -> bool:
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


def _is_ephemeral_candidate(rel_path: str) -> bool:
    p = rel_path.replace("\\", "/")
    lower = p.lower()
    if "/.github/workflows/" in lower and lower.endswith((".yml", ".yaml")):
        return True
    name = Path(p).name
    if name in _EPHEMERAL_CANDIDATE_NAMES:
        return True
    if name.startswith("Dockerfile"):
        return True
    if name.endswith(_EPHEMERAL_CANDIDATE_SUFFIXES):
        return True
    return False


def is_chaintrap_bootstrap_pr(
    repo_root: Path,
    *,
    base_ref: str,
    head_ref: str = "HEAD",
) -> bool:
    """True when Chaintrap is newly introduced in this PR (full ephemeral baseline)."""
    if not base_ref:
        return False
    root = repo_root.resolve()
    changed = _git_diff_name_only(root, base_ref, head_ref)
    for rel in changed:
        lower = rel.lower()
        if lower.endswith("chaintrap.yml") or lower.endswith(".chaintrap.yml"):
            if not _file_exists_at_ref(root, base_ref, rel):
                return True
        if "/.github/workflows/" in lower and lower.endswith((".yml", ".yaml")):
            if not _file_exists_at_ref(root, base_ref, rel):
                try:
                    text = (root / rel).read_text(encoding="utf-8")
                except OSError:
                    continue
                if any(marker in text for marker in _CHAINTRAP_WORKFLOW_MARKERS):
                    return True
            else:
                try:
                    head_text = (root / rel).read_text(encoding="utf-8")
                except OSError:
                    continue
                if "chaintrap-sec/scan-action" in head_text and _path_changed_between(
                    root, base_ref, head_ref, rel
                ):
                    base_text = _git_show_file(root, base_ref, rel)
                    if base_text is not None and "chaintrap-sec/scan-action" not in base_text:
                        return True
    return False


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


def discover_ephemeral_for_pr(
    workspace: Path,
    *,
    base_ref: str,
    head_ref: str = "HEAD",
    ecosystems: set[str] | None = None,
    paths: list[str] | None = None,
    max_items: int = 200,
) -> tuple[list[dict], str, bool]:
    """Return ephemeral packages for PR scan (full bootstrap or changed files only)."""
    root = workspace.resolve()
    bootstrap = is_chaintrap_bootstrap_pr(root, base_ref=base_ref, head_ref=head_ref)
    if bootstrap:
        items, mode = discover_ephemeral(
            root,
            paths=paths,
            ecosystems=ecosystems,
            max_items=max_items,
            candidate_files=None,
        )
        return items, f"{mode}-bootstrap", True

    changed = _git_diff_name_only(root, base_ref, head_ref)
    candidates = {rel for rel in changed if _is_ephemeral_candidate(rel)}
    if not candidates:
        return [], "ephemeral-diff-none", False

    items, mode = discover_ephemeral(
        root,
        paths=paths,
        ecosystems=ecosystems,
        max_items=max_items,
        candidate_files=candidates,
    )
    return items, mode, False
