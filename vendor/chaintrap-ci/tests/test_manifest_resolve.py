"""Tests for manifest compile resolution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from chaintrap_ci.discover_diff import discover_added_packages
from chaintrap_ci.manifest_resolve import (
    compile_requirements_text,
    packages_from_requirements_manifest,
    parse_compiled_requirements_text,
    requirements_has_unpinned_lines,
)


def _mock_uv_compile(req_path: Path) -> tuple[str | None, str]:
    text = req_path.read_text(encoding="utf-8")
    if "django>=4.2" in text:
        return "django==4.2.15\nasgiref==3.8.1\n", ""
    if "django>=4.0" in text:
        return "django==4.0.10\nasgiref==3.7.2\n", ""
    return "requests==2.32.0\n", ""


def test_requirements_has_unpinned_lines() -> None:
    assert requirements_has_unpinned_lines("django>=4.0\nrequests==2.31.0\n")
    assert not requirements_has_unpinned_lines("requests==2.31.0\n")


def test_parse_compiled_requirements_text() -> None:
    rows = parse_compiled_requirements_text("django==4.2.15\n# comment\n")
    assert rows == [
        {
            "ecosystem": "pypi",
            "package_spec": "django@4.2.15",
            "lockfile_path": None,
            "resolution_source": "compile",
        }
    ]


def test_compile_requirements_text_mock() -> None:
    result = compile_requirements_text(
        "django>=4.2\n",
        runner=_mock_uv_compile,
    )
    assert result.error is None
    specs = {r["package_spec"] for r in result.packages}
    assert "django@4.2.15" in specs
    assert result.packages[0].get("declared_constraint") == "django>=4.2"


def test_packages_from_requirements_manifest_pinned_only(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")
    pkgs, err = packages_from_requirements_manifest(req, resolve_manifests=True)
    assert err is None
    assert {p["package_spec"] for p in pkgs} == {"requests@2.31.0"}


def test_packages_from_requirements_manifest_compile(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("django>=4.2\n", encoding="utf-8")
    pkgs, err = packages_from_requirements_manifest(
        req,
        resolve_manifests=True,
        runner=_mock_uv_compile,
    )
    assert err is None
    specs = {p["package_spec"] for p in pkgs}
    assert "django@4.2.15" in specs


def test_discover_diff_compiled_range_bump(tmp_path: Path) -> None:
    import subprocess

    def _git(repo: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

    repo = tmp_path
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "test")
    _git(repo, "branch", "-M", "main")
    (repo / "requirements.txt").write_text("django>=4.0\n", encoding="utf-8")
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-m", "base")

    _git(repo, "checkout", "-b", "feature")
    (repo / "requirements.txt").write_text("django>=4.2\n", encoding="utf-8")
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-m", "bump range")

    with patch(
        "chaintrap_ci.manifest_resolve.compile_requirements_text",
        side_effect=lambda text, **kwargs: compile_requirements_text(
            text,
            runner=_mock_uv_compile,
            manifest_rel=kwargs.get("manifest_rel", ""),
        ),
    ):
        added, mode, warnings = discover_added_packages(
            repo,
            base_ref="main",
            head_ref="HEAD",
            ecosystems={"pypi"},
        )

    specs = {a["package_spec"] for a in added}
    assert "django@4.2.15" in specs
    assert mode == "diff-compiled-manifest"
    assert not warnings
