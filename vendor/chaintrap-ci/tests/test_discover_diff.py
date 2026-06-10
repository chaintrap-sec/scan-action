"""Tests for diff-aware lockfile discovery."""

from __future__ import annotations

import subprocess
from pathlib import Path

from chaintrap_ci.discover_diff import discover_added_packages

_ROOT_REQ = """requests==2.31.0
pyyaml==6.0.1
"""

_SIM_REQ = """durabletask==1.4.1
beautifulsoupp==0.0.1
"""

_PKG_LOCK = """{
  "name": "sim",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "sim", "version": "0.0.0", "dependencies": { "lodash": "4.17.21" } },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/@ctrl/tinycolor": { "version": "4.1.1" }
  }
}"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _init_repo(repo: Path) -> None:
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "test")


def test_discover_added_skips_unchanged_root_lockfile(tmp_path: Path) -> None:
    """New subfolder lockfile must not pull in unchanged root requirements.txt."""
    repo = tmp_path
    _init_repo(repo)
    _git(repo, "branch", "-M", "main")
    (repo / "requirements.txt").write_text(_ROOT_REQ, encoding="utf-8")
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-m", "base")

    _git(repo, "checkout", "-b", "feature")
    sim = repo / "chaintrap-attack-sim"
    sim.mkdir()
    (sim / "requirements.txt").write_text(_SIM_REQ, encoding="utf-8")
    (sim / "package-lock.json").write_text(_PKG_LOCK, encoding="utf-8")
    _git(repo, "add", "chaintrap-attack-sim")
    _git(repo, "commit", "-m", "add sim fixtures")

    added, mode = discover_added_packages(
        repo,
        base_ref="main",
        head_ref="HEAD",
        ecosystems={"npm", "pypi"},
    )
    specs = {a["package_spec"] for a in added}

    assert "requests@2.31.0" not in specs
    assert "pyyaml@6.0.1" not in specs
    assert "durabletask@1.4.1" in specs
    assert "beautifulsoupp@0.0.1" in specs
    assert "lodash@4.17.21" in specs
    assert "@ctrl/tinycolor@4.1.1" in specs
    assert mode == "diff-new-lockfile"


def test_discover_added_reports_delta_on_modified_lockfile(tmp_path: Path) -> None:
    repo = tmp_path
    _init_repo(repo)
    _git(repo, "branch", "-M", "main")
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-m", "base")

    _git(repo, "checkout", "-b", "feature")
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\nmalpkg==9.9.9\n", encoding="utf-8"
    )
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-m", "add dep")

    added, mode = discover_added_packages(
        repo,
        base_ref="main",
        head_ref="HEAD",
        ecosystems={"pypi"},
    )
    specs = {a["package_spec"] for a in added}

    assert specs == {"malpkg@9.9.9"}
    assert mode == "diff"
