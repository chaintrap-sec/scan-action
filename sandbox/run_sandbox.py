#!/usr/bin/env python3
"""Offline sandbox: E2E content + workflow + denylist coverage matrix."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "vendor" / "chaintrap-static-scan" / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "chaintrap-ci" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from build_artifacts import build  # noqa: E402
from mock_registry import MockRegistry  # noqa: E402

from chaintrap_ci.workflow_audit import audit_workflow_file  # noqa: E402
from chaintrap_static_scan.content_scan import scan_package_content  # noqa: E402
from chaintrap_static_scan.known_bad import clear_known_bad_cache, match as known_bad_match  # noqa: E402
from chaintrap_ci.workflow_audit import (  # noqa: E402
    audit_bundled_workflows,
    workflow_findings_to_content_hits,
)


def _rule_ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or "") for f in findings if f.get("rule_id")}


def _prefix_match(actual: set[str], expected: str) -> bool:
    return any(rid.startswith(expected) or expected.startswith(rid.rstrip("-")) for rid in actual)


def _check_expected(actual: set[str], expected: list[str], forbidden: list[str] | None) -> tuple[bool, list[str]]:
    issues: list[str] = []
    for exp in expected:
        if not any(rid.startswith(exp) or exp in rid for rid in actual):
            issues.append(f"missing expected rule prefix {exp}")
    for forb in forbidden or []:
        if any(rid.startswith(forb) for rid in actual):
            issues.append(f"unexpected forbidden rule prefix {forb} in {actual}")
    return not issues, issues


def main() -> int:
    manifest_path = SANDBOX / "corpus" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples = manifest.get("samples") or []

    artifact_dir = build()
    registry = MockRegistry(artifact_dir)
    registry.start()

    os.environ["CHAINTRAP_NPM_REGISTRY"] = registry.npm_base
    os.environ["CHAINTRAP_PYPI_BASE"] = registry.pypi_base
    clear_known_bad_cache()
    data_dir = ROOT / "data"

    def bundled_fn(dest: Path, eco: str) -> list[dict]:
        if eco != "npm":
            return []
        return workflow_findings_to_content_hits(audit_bundled_workflows(dest))

    rows: list[dict] = []
    failures = 0

    print("Chaintrap sandbox coverage matrix")
    print("=" * 72)

    for sample in samples:
        sid = str(sample.get("id") or "")
        kind = str(sample.get("kind") or "")
        benign = bool(sample.get("benign"))
        expected = list(sample.get("expected_rules") or [])
        forbidden = list(sample.get("forbidden_rules") or [])
        actual: set[str] = set()
        err: str | None = None

        if kind == "package":
            eco = str(sample.get("ecosystem") or "npm")
            name = str(sample.get("name") or "")
            version = str(sample.get("version") or "")
            findings, err = scan_package_content(
                eco,
                name,
                version,
                extra_findings_fn=bundled_fn,
            )
            actual = _rule_ids(findings)
        elif kind == "denylist":
            hit = known_bad_match(
                str(sample.get("ecosystem") or "npm"),
                str(sample.get("name") or ""),
                str(sample.get("version") or ""),
                data_dir=data_dir,
            )
            if hit:
                actual = {str(hit.get("rule_id") or "")}
        elif kind == "workflow":
            wf_file = SANDBOX / "corpus" / "workflows" / str(sample.get("file") or "")
            with tempfile.TemporaryDirectory() as td:
                dest = Path(td) / ".github" / "workflows"
                dest.mkdir(parents=True)
                wf_copy = dest / wf_file.name
                wf_copy.write_text(wf_file.read_text(encoding="utf-8"), encoding="utf-8")
                from chaintrap_ci.workflow_audit import audit_workflows

                actual = _rule_ids(audit_workflows(Path(td)))
        else:
            err = f"unknown kind {kind}"

        ok, issues = _check_expected(actual, expected, forbidden if benign else None)
        if err:
            issues.append(err)
        status = "PASS" if ok and not err else "FAIL"
        if status != "PASS":
            failures += 1

        rows.append(
            {
                "id": sid,
                "kind": kind,
                "benign": benign,
                "status": status,
                "expected": expected,
                "actual": sorted(actual),
                "issues": issues,
            }
        )
        print(f"{status:4}  {sid:24}  {kind:10}  rules={sorted(actual)}")

    registry.stop()

    print("=" * 72)
    passed = sum(1 for r in rows if r["status"] == "PASS")
    print(f"Results: {passed}/{len(rows)} passed, {failures} failed")

    report_path = SANDBOX / "artifacts" / "coverage_report.json"
    report_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"Report: {report_path}")

    if failures:
        print("\nGaps:")
        for r in rows:
            if r["status"] != "PASS":
                print(f"  - {r['id']}: {r['issues']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
