"""Tests for ephemeral dependency discovery (v1.4)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test_fixtures" / "ephemeral_deps"
VENDOR_CI = ROOT / "vendor" / "chaintrap-ci" / "src"
VENDOR_STATIC = ROOT / "vendor" / "chaintrap-static-scan" / "src"
VENDOR_GUARD = ROOT / "vendor" / "chaintrap-guard" / "src"
SCRIPTS = ROOT / "scripts"

for p in (SCRIPTS, VENDOR_CI, VENDOR_STATIC, VENDOR_GUARD):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from chaintrap_ci.ephemeral_discover import (  # noqa: E402
    discover_ephemeral,
    hide_ephemeral_in_lockfile,
)
from chaintrap_ci.ephemeral_discover_diff import is_chaintrap_bootstrap_pr  # noqa: E402
from chaintrap_ci.ephemeral_shell import extract_specs_from_command, split_shell_line  # noqa: E402
from chaintrap_ci.scan import ScanConfig, evaluate_scan_rollup, run_local_scan  # noqa: E402
from chaintrap_ci.summary import format_summary_markdown  # noqa: E402


def test_split_shell_line_compound():
    parts = split_shell_line("pip install foo==1.0.0 && npx bar@2.0.0")
    assert len(parts) == 2
    assert "pip install" in parts[0]
    assert "npx" in parts[1]


def test_extract_npx_spec():
    rows = extract_specs_from_command("npx -y nx@20.9.0", ecosystems={"npm"})
    assert len(rows) == 1
    assert rows[0]["package_spec"] == "nx@20.9.0"


def test_extract_pip_and_uvx():
    pip_rows = extract_specs_from_command("pip install requests==2.31.0", ecosystems={"pypi"})
    assert pip_rows[0]["name"] == "requests"
    uvx_rows = extract_specs_from_command("uvx ruff@0.4.0", ecosystems={"pypi"})
    assert uvx_rows[0]["package_spec"] == "ruff@0.4.0"


def test_discover_ephemeral_npx_workflow():
    items, mode = discover_ephemeral(FIXTURES / "npx", ecosystems={"npm"})
    specs = {i["package_spec"] for i in items}
    assert "nx@20.9.0" in specs
    assert mode.startswith("ephemeral")


def test_discover_ephemeral_pip_workflow():
    items, _ = discover_ephemeral(FIXTURES / "pip", ecosystems={"pypi"})
    assert any(i["package_spec"] == "requests@2.31.0" for i in items)


def test_discover_ephemeral_dockerfile_and_shell():
    root = FIXTURES
    items, _ = discover_ephemeral(root, ecosystems={"npm", "pypi"})
    specs = {i["package_spec"] for i in items}
    assert "django@5.0.1" in specs
    assert "requests@unknown" in specs
    assert "prettier@3.0.0" in specs


def test_hide_ephemeral_in_lockfile():
    ephemeral = [
        {"ecosystem": "npm", "package_spec": "eslint@8.57.0"},
        {"ecosystem": "npm", "package_spec": "flask@3.0.0"},
    ]
    lockfile = [{"ecosystem": "npm", "package_spec": "eslint@8.57.0"}]
    hidden = hide_ephemeral_in_lockfile(ephemeral, lockfile)
    assert len(hidden) == 1
    assert hidden[0]["package_spec"] == "flask@3.0.0"


def test_bootstrap_detects_new_chaintrap_workflow(tmp_path: Path):
    wf = tmp_path / ".github" / "workflows" / "chaintrap.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("uses: chaintrap-sec/scan-action@v1\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t.com", "-c", "user.name=t", "commit", "-m", "init"],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )
    assert is_chaintrap_bootstrap_pr(tmp_path, base_ref="", head_ref="HEAD") is False


@patch("chaintrap_ci.scan.scan_packages")
@patch("chaintrap_ci.scan.fetch_org_iocs", return_value={})
def test_ephemeral_known_bad_blocks(mock_ioc, mock_osv):
    from chaintrap_static_scan.known_bad import match as known_bad_match
    from chaintrap_static_scan.models import OsvFinding

    mock_osv.return_value = {}
    rollup = run_local_scan(
        FIXTURES / "npx",
        cfg=ScanConfig(
            max_packages=50,
            diff_mode=False,
            ephemeral_scan_enabled=True,
            heuristics_enabled=False,
            content_scan_enabled=False,
        ),
        data_dir=ROOT / "data",
    )
    items = rollup.get("items") or []
    nx_items = [i for i in items if "nx@" in str(i.get("package_spec"))]
    assert nx_items, "expected ephemeral nx package"
    kb = known_bad_match("npm", "nx", "20.9.0", data_dir=ROOT / "data")
    assert kb is not None
    exit_code, blocked, _ = evaluate_scan_rollup(rollup, ScanConfig(fail_on_mal=True))
    assert exit_code == 2
    assert blocked


def test_summary_renders_ephemeral_section():
    rollup = {
        "bundle_id": "test",
        "bundle_status": "complete",
        "scan_mode": "runner-osv-ioc",
        "discovery_mode": "ephemeral-full",
        "ephemeral_bootstrap": True,
        "items": [
            {
                "ecosystem": "npm",
                "package_spec": "nx@20.9.0",
                "resolution_source": "ephemeral",
                "ephemeral_source": {
                    "file": ".github/workflows/ci.yml",
                    "line": 7,
                    "kind": "workflow",
                    "command": "npx -y nx@20.9.0",
                },
                "summary": {"verdict_level": "BLOCK", "risk_tldr": "Known bad"},
            }
        ],
    }
    md = format_summary_markdown(rollup, blocked=[], warned=[], gate_summary="test")
    assert "Ephemeral dependencies" in md
    assert "First Chaintrap scan" in md
    assert "nx@20.9.0" in md
