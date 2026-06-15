"""Regression tests for developer-facing risk narrative and blocking policy."""

from __future__ import annotations

from chaintrap_ci.risk_narrative import (
    dedupe_content_findings,
    enrich_summary_with_risk_narrative,
    has_block_tier_content,
)
from chaintrap_ci.scan import ScanConfig, evaluate_scan_rollup


def _hit(rule_id: str, *, severity: str = "HIGH", category: str = "process", n: int = 1) -> list[dict]:
    return [
        {
            "rule_id": rule_id,
            "severity": severity,
            "category": category,
            "message": f"test {rule_id}",
            "file": f"src/pkg_{i}.py",
            "line": i + 1,
            "snippet": f"{rule_id}()",
        }
        for i in range(n)
    ]


def _norsodikin_findings() -> list[dict]:
    findings: list[dict] = []
    findings.extend(_hit("dynamic_import_dunder", severity="LOW", category="dynamic_import", n=30))
    findings.extend(_hit("requests_http", severity="LOW", category="network", n=25))
    findings.extend(_hit("os_system", severity="HIGH", category="process", n=1))
    findings.extend(_hit("subprocess_spawn", severity="HIGH", category="process", n=7))
    return findings


def test_norsodikin_review_not_block():
    summary = enrich_summary_with_risk_narrative({}, _norsodikin_findings())
    assert summary["verdict_level"] in ("REVIEW", "WARN")
    assert summary["verdict_level"] != "BLOCK"
    assert not has_block_tier_content(summary)
    assert 4.0 <= float(summary["risk_score"]) <= 8.5
    assert "shell" in summary["risk_tldr"].lower() or "subprocess" in summary["risk_tldr"].lower()
    assert summary["risk_themes"]["credential_access"]["status"] == "not_detected"
    assert summary["risk_themes"]["data_exfiltration"]["status"] == "not_detected"
    assert summary["risk_themes"]["shell_execution"]["status"] == "found"
    deduped, raw = dedupe_content_findings(_norsodikin_findings())
    assert raw == 63
    assert len(deduped) == 4
    assert len(summary["top_evidence"]) <= 5
    assert summary["suppressed_count"] > 40


def test_mal_osv_blocks_at_10():
    summary = enrich_summary_with_risk_narrative(
        {"malicious_osv_ids": ["MAL-2024-1234"], "malware_risk": "CRITICAL"},
        [],
    )
    assert summary["verdict_level"] == "BLOCK"
    assert summary["risk_score"] == 10.0
    assert "malicious" in summary["risk_tldr"].lower()


def test_benign_requests_pass():
    summary = enrich_summary_with_risk_narrative(
        {"verdict_level": "PASS", "malware_risk": "NONE"},
        _hit("requests_http", severity="LOW", category="network", n=5),
    )
    assert summary["verdict_level"] in ("PASS", "INFO", "WARN")
    assert summary["verdict_level"] != "BLOCK"
    assert not has_block_tier_content(summary)


def test_block_tier_content_blocks_rollup():
    findings = _hit("exec_urllib_urlopen_chain", severity="CRITICAL", category="installer_hook", n=1)
    summary = enrich_summary_with_risk_narrative({}, findings)
    assert has_block_tier_content(summary)
    assert summary["verdict_level"] == "BLOCK"

    rollup = {
        "bundle_status": "complete",
        "items": [
            {
                "ecosystem": "pypi",
                "package_spec": "evil@1.0.0",
                "summary": summary,
            }
        ],
    }
    exit_code, blocked, warned = evaluate_scan_rollup(rollup, ScanConfig(fail_on_mal=True))
    assert exit_code == 2
    assert len(blocked) == 1


def test_review_tier_shell_only_warns_not_blocks():
    summary = enrich_summary_with_risk_narrative({}, _hit("os_system", severity="HIGH", n=1))
    rollup = {
        "bundle_status": "complete",
        "items": [{"ecosystem": "pypi", "package_spec": "norsodikin@1.0.7.1", "summary": summary}],
    }
    exit_code, blocked, warned = evaluate_scan_rollup(rollup, ScanConfig(fail_on_mal=True))
    assert exit_code in (0, 1)
    assert not blocked
    assert len(warned) == 1
