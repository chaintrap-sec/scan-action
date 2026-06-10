"""Tests for chaintrap_ci.scan merge and gating."""

from __future__ import annotations

from unittest.mock import patch

from chaintrap_static_scan.models import OsvFinding, PackageKey

from chaintrap_ci.scan import ScanConfig, evaluate_scan_rollup, run_local_scan


def test_evaluate_blocks_on_ioc_hit():
    rollup = {
        "items": [
            {
                "ecosystem": "npm",
                "package_spec": "evil@1.0.0",
                "summary": {"ioc_hit": True, "ioc_severity": "CRITICAL", "malware_risk": "CRITICAL"},
            }
        ]
    }
    code, blocked, _ = evaluate_scan_rollup(rollup, ScanConfig())
    assert code == 2
    assert len(blocked) == 1


def test_evaluate_warns_on_cve_when_fail_on_cve_none():
    rollup = {
        "items": [
            {
                "ecosystem": "npm",
                "package_spec": "lodash@4.17.21",
                "summary": {
                    "ioc_hit": False,
                    "malware_risk": "NONE",
                    "vulnerability_risk": "HIGH",
                    "vulnerable_osv_ids": ["GHSA-abc"],
                },
            }
        ]
    }
    code, blocked, warned = evaluate_scan_rollup(rollup, ScanConfig(fail_on_cve="none"))
    assert code == 1
    assert not blocked
    assert len(warned) == 1


def test_evaluate_blocks_on_mal_when_enabled():
    rollup = {
        "items": [
            {
                "ecosystem": "npm",
                "package_spec": "bad@1.0.0",
                "summary": {
                    "ioc_hit": False,
                    "malware_risk": "CRITICAL",
                    "malicious_osv_ids": ["MAL-2024-1"],
                },
            }
        ]
    }
    code, blocked, _ = evaluate_scan_rollup(rollup, ScanConfig(fail_on_mal=True))
    assert code == 2
    assert blocked


@patch("chaintrap_ci.scan.fetch_org_iocs")
@patch("chaintrap_ci.scan.scan_packages")
@patch("chaintrap_ci.scan.discover")
def test_run_local_scan_merges_ioc(mock_discover, mock_osv, mock_ioc, tmp_path):
    mock_discover.return_value = [{"ecosystem": "npm", "package_spec": "evil@1.0.0"}]
    pk = PackageKey(host="github-actions", ecosystem="npm", name="evil", version="1.0.0")
    mock_osv.return_value = {pk: OsvFinding(malicious_ids=[], vulnerable_ids=[], query_error=None)}
    mock_ioc.return_value = {
        ("npm", "evil", "1.0.0"): {
            "ecosystem": "npm",
            "package_name": "evil",
            "package_version": "1.0.0",
            "severity": "CRITICAL",
            "source": "manual",
            "ioc_key": "npm:evil@1.0.0",
        }
    }
    rollup = run_local_scan(
        tmp_path,
        supabase_url="https://x.supabase.co",
        supabase_key="key",
        org_id="org-acme",
    )
    assert rollup["scan_mode"].startswith("runner-osv-ioc")
    item = rollup["items"][0]
    assert item["summary"]["ioc_hit"] is True
