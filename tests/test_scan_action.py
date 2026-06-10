"""Tests for chaintrap-scan-action."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
VENDOR_CI = ROOT / "vendor" / "chaintrap-ci" / "src"
VENDOR_STATIC = ROOT / "vendor" / "chaintrap-static-scan" / "src"

for p in (SCRIPTS, VENDOR_CI, VENDOR_STATIC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from chaintrap_ci.discover import discover_packages  # noqa: E402
from chaintrap_policy import load_policy  # noqa: E402
from chaintrap_sarif import rollup_json_to_sarif  # noqa: E402
from chaintrap_workflow_audit import audit_workflows  # noqa: E402


FIXTURES = ROOT / "test_fixtures"
MAL = FIXTURES / "malicious_dep_test"
WF = FIXTURES / "workflow_audit"


def test_discover_malicious_fixture():
    items = discover_packages(MAL, {"npm", "pypi"}, max_items=50)
    specs = {i["package_spec"] for i in items}
    assert "ts-logger-pack@1.1.3" in specs
    assert any("telnyx@" in s for s in specs)


def test_discover_yarn_lock():
    yarn_dir = ROOT / "tests" / "fixtures" / "yarn_project"
    items = discover_packages(yarn_dir, {"npm"}, max_items=50)
    assert any(i["package_spec"] == "lodash@4.17.21" for i in items)


def test_discover_pipfile_lock():
    pip_dir = ROOT / "tests" / "fixtures" / "pipfile_project"
    items = discover_packages(pip_dir, {"pypi"}, max_items=50)
    assert any("requests@" in i["package_spec"] for i in items)


def test_workflow_audit_finds_pwn_request():
    findings = audit_workflows(WF)
    rules = {f["rule_id"] for f in findings}
    assert "CTW-001" in rules
    assert any(f["severity"] == "CRITICAL" for f in findings)


def test_policy_loader():
    pol = load_policy(MAL)
    assert pol.minimum_release_age_days == 7
    assert pol.audit_workflows is True


def test_sarif_includes_workflow_findings():
    rollup = {
        "bundle_id": "test",
        "items": [],
        "workflow_findings": [
            {
                "rule_id": "CTW-001",
                "severity": "CRITICAL",
                "message": "test",
                "file": ".github/workflows/x.yml",
                "line": 3,
            }
        ],
    }
    doc = rollup_json_to_sarif(rollup)
    assert doc["runs"][0]["results"]


@pytest.mark.integration
def test_scan_blocks_malicious_fixture():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(VENDOR_CI), str(VENDOR_STATIC), str(SCRIPTS)]
    )
    cmd = [
        sys.executable,
        str(SCRIPTS / "chaintrap_gha_scan.py"),
        "--action-root",
        str(ROOT),
        "--workspace",
        str(MAL),
        "--paths",
        ".",
        "--heuristics",
        "false",
        "--audit-workflows",
        "false",
        "--fail-on-mal",
        "true",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    assert result.returncode == 2, result.stdout + result.stderr


def test_heuristics_typosquat():
    from chaintrap_static_scan.heuristics import check_typosquat

    hit = check_typosquat("npm", "lodahs", data_dir=ROOT / "data")
    assert hit is not None
    assert hit["rule_id"] == "CTH-003"
