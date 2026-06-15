"""Diff-aware lockfile discovery for pull_request events."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from chaintrap_ci.discover import (
    _LOCKFILE_NAMES,
    _MANIFEST_NAMES,
    _dedupe_items,
    _iter_lockfiles,
    _iter_manifests,
    _parse_lockfile,
    _resolve_search_dirs,
)
from chaintrap_ci.manifest_resolve import (
    compile_package_json_path,
    dir_has_npm_lockfile,
    dir_has_pypi_lockfile,
    packages_from_requirements_text,
    parse_compiled_requirements_text,
    requirements_has_unpinned_lines,
)


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


def _path_changed_between(
    repo_root: Path, base_ref: str, head_ref: str, rel_path: str
) -> bool:
    """True when file content differs between base and head (PR range)."""
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


_lockfile_changed_between = _path_changed_between


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


def _row_set(rows: list[dict]) -> set[tuple[str, str]]:
    return {
        (str(r.get("ecosystem") or ""), str(r.get("package_spec") or ""))
        for r in rows
        if r.get("ecosystem") and r.get("package_spec")
    }


def _rows_for_requirements_diff(
    repo_root: Path,
    ref: str,
    rel: str,
    head_path: Path,
    *,
    resolve_manifests: bool,
) -> tuple[list[dict], str | None]:
    if ref == "HEAD" or not ref:
        try:
            text = head_path.read_text(encoding="utf-8")
        except OSError:
            return [], "read failed"
    else:
        text = _git_show_file(repo_root, ref, rel)
        if text is None:
            return [], None

    if requirements_has_unpinned_lines(text):
        if dir_has_pypi_lockfile(head_path.parent):
            return [], None
        return packages_from_requirements_text(
            text,
            resolve_manifests=resolve_manifests,
            manifest_rel=rel,
        )

    return parse_compiled_requirements_text(text, manifest_path=rel), None


def _rows_for_package_json_diff(
    repo_root: Path,
    ref: str,
    rel: str,
    head_path: Path,
    *,
    resolve_manifests: bool,
) -> tuple[list[dict], str | None]:
    if not resolve_manifests:
        return [], "package.json compile disabled (resolve-manifests=false)"

    if ref == "HEAD" or not ref:
        result = compile_package_json_path(head_path, manifest_rel=rel)
    else:
        text = _git_show_file(repo_root, ref, rel)
        if text is None:
            return [], None
        with tempfile.TemporaryDirectory(prefix="chaintrap_pkg_") as td:
            pkg_path = Path(td) / "package.json"
            pkg_path.write_text(text, encoding="utf-8")
            result = compile_package_json_path(pkg_path, manifest_rel=rel)

    if result.error:
        return [], result.error
    return result.packages, None


def discover_added_packages(
    workspace: Path,
    *,
    base_ref: str,
    head_ref: str = "HEAD",
    ecosystems: set[str] | None = None,
    paths: list[str] | None = None,
    max_items: int = 200,
    resolve_manifests: bool = True,
) -> tuple[list[dict], str, list[dict]]:
    """Return packages present in head lockfiles but not in base (PR delta)."""
    root = workspace.resolve()
    wanted = ecosystems or {"npm", "pypi"}
    warnings: list[dict] = []

    search_dirs = _resolve_search_dirs(root, ",".join(paths) if paths else ".")
    head_locks: list[Path] = []
    head_manifests: list[Path] = []
    for search_dir in search_dirs:
        head_locks.extend(_iter_lockfiles(search_dir))
        head_manifests.extend(_iter_manifests(search_dir))

    added: list[dict] = []
    seen: set[tuple[str, str]] = set()
    mode = "diff"
    saw_new_lockfile = False
    saw_compiled_manifest = False

    if not head_locks and not head_manifests:
        return [], "no-lockfiles", warnings

    for lock_path in head_locks:
        eco = _LOCKFILE_NAMES.get(lock_path.name)
        if not eco or eco not in wanted:
            continue

        rel = lock_path.relative_to(root).as_posix()
        if base_ref and not _path_changed_between(root, base_ref, head_ref, rel):
            continue

        if lock_path.name == "requirements.txt":
            head_rows, head_err = _rows_for_requirements_diff(
                root,
                head_ref,
                rel,
                lock_path,
                resolve_manifests=resolve_manifests,
            )
            if head_err:
                warnings.append({"manifest": rel, "error": head_err})
            if base_ref and _lockfile_exists_at_ref(root, base_ref, rel):
                base_rows, base_err = _rows_for_requirements_diff(
                    root,
                    base_ref,
                    rel,
                    lock_path,
                    resolve_manifests=resolve_manifests,
                )
                if base_err:
                    warnings.append({"manifest": rel, "error": f"base: {base_err}"})
                delta_keys = _row_set(head_rows) - _row_set(base_rows)
            else:
                delta_keys = _row_set(head_rows)
                saw_new_lockfile = True

            if requirements_has_unpinned_lines(lock_path.read_text(encoding="utf-8")):
                saw_compiled_manifest = True

            row_by_key = {
                (str(r.get("ecosystem") or ""), str(r.get("package_spec") or "")): r
                for r in head_rows
            }
            for eco_key, spec in sorted(delta_keys):
                key = (eco_key, spec.lower())
                if key in seen:
                    continue
                seen.add(key)
                src = row_by_key.get((eco_key, spec), {})
                added.append(
                    {
                        "ecosystem": eco_key,
                        "package_spec": spec,
                        "lockfile": rel,
                        "lockfile_path": rel,
                        "resolution_source": src.get("resolution_source", "lockfile"),
                        "declared_constraint": src.get("declared_constraint"),
                    }
                )
            continue

        head_rows = _parse_lockfile(lock_path, resolve_manifests=resolve_manifests)
        head_set = _row_set(head_rows)

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
                    "lockfile_path": rel,
                    "resolution_source": "lockfile",
                }
            )

    for manifest_path in head_manifests:
        eco = _MANIFEST_NAMES.get(manifest_path.name)
        if not eco or eco not in wanted:
            continue
        if dir_has_npm_lockfile(manifest_path.parent):
            continue

        rel = manifest_path.relative_to(root).as_posix()
        if base_ref and not _path_changed_between(root, base_ref, head_ref, rel):
            continue

        head_rows, head_err = _rows_for_package_json_diff(
            root,
            head_ref,
            rel,
            manifest_path,
            resolve_manifests=resolve_manifests,
        )
        if head_err:
            warnings.append({"manifest": rel, "error": head_err})
            continue

        if base_ref and _lockfile_exists_at_ref(root, base_ref, rel):
            base_rows, base_err = _rows_for_package_json_diff(
                root,
                base_ref,
                rel,
                manifest_path,
                resolve_manifests=resolve_manifests,
            )
            if base_err:
                warnings.append({"manifest": rel, "error": f"base: {base_err}"})
            delta_keys = _row_set(head_rows) - _row_set(base_rows)
        else:
            delta_keys = _row_set(head_rows)
            saw_compiled_manifest = True

        saw_compiled_manifest = True
        row_by_key = {
            (str(r.get("ecosystem") or ""), str(r.get("package_spec") or "")): r
            for r in head_rows
        }
        for eco_key, spec in sorted(delta_keys):
            key = (eco_key, spec.lower())
            if key in seen:
                continue
            seen.add(key)
            src = row_by_key.get((eco_key, spec), {})
            added.append(
                {
                    "ecosystem": eco_key,
                    "package_spec": spec,
                    "lockfile": rel,
                    "lockfile_path": rel,
                    "resolution_source": src.get("resolution_source", "compile"),
                }
            )

    if saw_compiled_manifest:
        mode = "diff-compiled-manifest"
    elif saw_new_lockfile:
        mode = "diff-new-lockfile"

    deduped = _dedupe_items(added)
    if max_items > 0:
        deduped = deduped[:max_items]
    return deduped, mode, warnings
