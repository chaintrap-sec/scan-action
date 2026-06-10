"""Phase 2 tests: resilience, content scan, fail_on_error."""

from __future__ import annotations

import io
import sys
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
VENDOR_CI = ROOT / "vendor" / "chaintrap-ci" / "src"
VENDOR_STATIC = ROOT / "vendor" / "chaintrap-static-scan" / "src"
SCRIPTS = ROOT / "scripts"

for p in (SCRIPTS, VENDOR_CI, VENDOR_STATIC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from chaintrap_ci.scan import ScanConfig, evaluate_scan_rollup  # noqa: E402
from chaintrap_static_scan.content_scan import safe_extract_tar, safe_extract_zip  # noqa: E402
from chaintrap_static_scan.heuristics import run_heuristics_batch  # noqa: E402
from chaintrap_static_scan.http_utils import http_get_json  # noqa: E402
from chaintrap_static_scan.pattern_scanner import scan_tree  # noqa: E402


def test_http_get_json_retries_on_failure():
    calls = {"n": 0}

    def fake_urlopen(req, timeout=0):
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("transient")
        raise AssertionError("should not reach")

    with patch("chaintrap_static_scan.http_utils.urllib.request.urlopen", side_effect=fake_urlopen):
        data, err = http_get_json("https://example.test/x", retries=2, backoff=0)
    assert data is None
    assert err is not None
    assert calls["n"] == 2


def test_safe_extract_tar_rejects_traversal():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name="../evil.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"evil"))
    dest = Path(__file__).parent / "_tmp_tar"
    dest.mkdir(exist_ok=True)
    try:
        with pytest.raises(ValueError, match="unsafe"):
            safe_extract_tar(buf.getvalue(), dest)
    finally:
        if dest.exists():
            dest.rmdir()


def test_safe_extract_zip_ok():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("pkg/index.js", "console.log('ok')")
    dest = Path(__file__).parent / "_tmp_zip"
    dest.mkdir(exist_ok=True)
    try:
        safe_extract_zip(buf.getvalue(), dest)
        assert (dest / "pkg" / "index.js").is_file()
    finally:
        import shutil

        shutil.rmtree(dest, ignore_errors=True)


def test_scan_tree_npm_malicious_fixture():
    tree = ROOT / "tests" / "fixtures" / "malicious_npm_pkg"
    hits = scan_tree(tree, "npm")
    rules = {h.rule_id for h in hits}
    assert "CTC-PE013" in rules or "CTC-PE007" in rules
    assert "CTC-OBF001" in rules


def test_fail_on_error_blocks_partial_bundle():
    rollup = {
        "bundle_status": "partial",
        "items": [
            {
                "package_spec": "foo@1.0.0",
                "ecosystem": "npm",
                "summary": {
                    "verdict_level": "WARN",
                    "osv_error": "timeout",
                    "malware_risk": "—",
                    "vulnerability_risk": "—",
                    "ioc_hit": False,
                    "heuristic_findings": [],
                    "content_findings": [],
                },
            }
        ],
    }
    cfg_warn = ScanConfig(fail_on_error=False)
    cfg_block = ScanConfig(fail_on_error=True)
    assert evaluate_scan_rollup(rollup, cfg_warn)[0] == 1
    assert evaluate_scan_rollup(rollup, cfg_block)[0] == 2


def test_content_findings_block_critical():
    rollup = {
        "bundle_status": "complete",
        "items": [
            {
                "package_spec": "evil@9.9.9",
                "ecosystem": "npm",
                "summary": {
                    "verdict_level": "BLOCK",
                    "malware_risk": "CRITICAL",
                    "vulnerability_risk": "NONE",
                    "ioc_hit": False,
                    "malicious_osv_ids": [],
                    "vulnerable_osv_ids": [],
                    "heuristic_findings": [],
                    "content_findings": [
                        {
                            "rule_id": "CTC-PE013",
                            "severity": "CRITICAL",
                            "message": "PowerShell bypass",
                            "file": "index.js",
                            "line": 2,
                        }
                    ],
                },
            }
        ],
    }
    exit_code, blocked, _ = evaluate_scan_rollup(rollup, ScanConfig())
    assert exit_code == 2
    assert blocked


def test_heuristics_batch_dedupes_npm_fetch():
    fetch_count = {"n": 0}
    meta = {"time": "2026-01-01T00:00:00.000Z", "scripts": {"postinstall": "node x.js"}}

    def fake_fetch(name, version):
        fetch_count["n"] += 1
        return meta

    with patch(
        "chaintrap_static_scan.heuristics._fetch_npm_version_meta",
        side_effect=fake_fetch,
    ):
        out = run_heuristics_batch(
            [("npm", "lodash", "4.17.21"), ("npm", "lodash", "4.17.21")],
            minimum_release_age_days=0,
        )
    assert fetch_count["n"] == 1
    assert ("npm", "lodash", "4.17.21") in out
