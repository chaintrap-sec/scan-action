"""Security abuse tests — path escape, injection, SSRF policy."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI_SRC = ROOT / "vendor" / "chaintrap-ci" / "src"
STATIC_SRC = ROOT / "vendor" / "chaintrap-static-scan" / "src"
SCRIPTS = ROOT / "scripts"
for p in (CI_SRC, STATIC_SRC, SCRIPTS):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from chaintrap_ci.discover import _resolve_search_dirs  # noqa: E402
from chaintrap_ci.ioc_client import fetch_org_iocs  # noqa: E402
from chaintrap_ci.security_sanitize import escape_markdown_inline, sanitize_gha_field  # noqa: E402
from chaintrap_ci.summary import format_summary_markdown  # noqa: E402
from chaintrap_gha_scan import gh_actions_error_annotation, gh_actions_workflow_annotation  # noqa: E402
from chaintrap_static_scan.content_scan import _download_and_extract  # noqa: E402
from chaintrap_static_scan.url_policy import (  # noqa: E402
    validate_api_report_url,
    validate_npm_tarball_url,
    validate_pypi_artifact_url,
    validate_supabase_url,
)


def test_paths_cannot_escape_workspace(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    dirs = _resolve_search_dirs(root, "../outside")
    assert dirs == [root.resolve()]
    assert outside.resolve() not in dirs

    dirs2 = _resolve_search_dirs(root, "app,../../outside")
    assert all(d.resolve().is_relative_to(root.resolve()) for d in dirs2)


def test_annotation_sanitizes_newlines():
    item = {
        "package_spec": "evil\n::error title=pwn::owned",
        "ecosystem": "npm",
        "_worst_severity": "HIGH",
    }
    line = gh_actions_error_annotation(item)
    assert "\n" not in line
    assert "::error title=pwn::" not in line

    wf = {
        "rule_id": "CTW-001",
        "severity": "HIGH",
        "message": "bad\n::warning::injected",
        "file": ".github/workflows/ci.yml",
        "line": 1,
    }
    wf_line = gh_actions_workflow_annotation(wf)
    assert "\n" not in wf_line
    assert wf_line.startswith("::error")


def test_summary_escapes_table_injection():
    rollup = {
        "bundle_id": "scan-1",
        "bundle_status": "complete",
        "items": [],
    }
    blocked = [
        {
            "ecosystem": "npm",
            "package_spec": "pkg|inject@1.0.0",
            "summary": {
                "verdict_level": "BLOCK",
                "risk_tldr": "bad | cell",
                "top_evidence": [],
            },
            "_worst_severity": "HIGH",
        }
    ]
    md = format_summary_markdown(rollup, blocked=blocked, warned=[], gate_summary="mal=block")
    assert "`pkg'inject@1.0.0`" in md or "pkg" in md
    assert "<!-- chaintrap-sca -->" in md
    lines = md.splitlines()
    table_lines = [ln for ln in lines if ln.startswith("|") and "Blocked" not in ln and "---" not in ln]
    for row in table_lines:
        if row.count("|") >= 3:
            cells = row.split("|")
            assert all("\n" not in c for c in cells)


def test_summary_marker_not_injectable():
    rollup = {"bundle_id": "x", "bundle_status": "complete", "items": []}
    blocked = [
        {
            "ecosystem": "npm",
            "package_spec": "x@1.0.0",
            "summary": {
                "verdict_level": "BLOCK",
                "risk_tldr": "<!-- chaintrap-sca --> fake pass",
                "top_evidence": [],
            },
            "_worst_severity": "HIGH",
        }
    ]
    md = format_summary_markdown(rollup, blocked=blocked, warned=[], gate_summary="mal=block")
    assert md.count("<!-- chaintrap-sca -->") == 1
    assert "(chaintrap-marker)" in md


def test_api_url_blocks_non_https():
    assert validate_api_report_url("http://api.chaintrap.com/x") is not None
    assert validate_api_report_url("https://evil.example.com/x") is not None


def test_api_url_allows_chaintrap():
    assert validate_api_report_url("https://api.chaintrap.com") is None


def test_api_url_blocks_metadata_ip():
    assert validate_api_report_url("https://169.254.169.254/latest") is not None


def test_supabase_host_allowlist():
    assert validate_supabase_url("https://evil.com") is not None
    assert validate_supabase_url("https://abc123.supabase.co") is None


def test_supabase_fetch_rejects_evil_host():
    with pytest.raises(RuntimeError, match="rejected"):
        fetch_org_iocs("https://evil.com", "key", "org-1")


def test_tarball_url_host_rejected(tmp_path: Path):
    err = _download_and_extract(
        "https://169.254.169.254/evil.tgz",
        tmp_path,
        max_bytes=1024,
        url_validator=lambda u: validate_npm_tarball_url(u),
    )
    assert err is not None
    assert "blocked" in err.lower() or "not allowed" in err.lower()


def test_npm_tarball_allows_registry():
    assert (
        validate_npm_tarball_url("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz")
        is None
    )


def test_pypi_artifact_allows_cdn():
    assert (
        validate_pypi_artifact_url(
            "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.0-py3-none-any.whl"
        )
        is None
    )


def test_escape_markdown_inline_strips_details():
    s = escape_markdown_inline("x</details>\ny")
    assert "</details>" not in s.lower()
    assert "\n" not in s


def test_sanitize_gha_field_percent():
    assert "%" in sanitize_gha_field("100%")  # encoded as %25
