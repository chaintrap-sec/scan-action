#!/usr/bin/env python3
"""Chaintrap GitHub Actions runner-local dependency + workflow security scan."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

_ACTION_ROOT = Path(__file__).resolve().parents[1]
_CI_SRC = _ACTION_ROOT / "vendor" / "chaintrap-ci" / "src"
_STATIC_SRC = _ACTION_ROOT / "vendor" / "chaintrap-static-scan" / "src"
_SCRIPTS = Path(__file__).resolve().parent
for _p in (_CI_SRC, _STATIC_SRC, _SCRIPTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from chaintrap_ci.scan import ScanConfig, evaluate_scan_rollup, run_local_scan  # noqa: E402
from chaintrap_policy import ChaintrapPolicy, load_policy  # noqa: E402
from chaintrap_sarif import rollup_json_to_sarif  # noqa: E402
from chaintrap_workflow_audit import audit_workflows  # noqa: E402

_SEV_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "MODERATE": 2,
    "LOW": 1,
    "NONE": 0,
    "UNKNOWN": 0,
}


def _gate_summary(cfg: ScanConfig) -> str:
    mal = "block" if cfg.fail_on_mal else "off"
    err = "block" if cfg.fail_on_error else "warn"
    content = "on" if cfg.content_scan_enabled else "off"
    return (
        f"ioc={cfg.fail_on_ioc}, mal={mal}, cve={cfg.fail_on_cve}, "
        f"diff={cfg.diff_mode}, content={content}, errors={err}"
    )


def _item_summary(item: dict[str, Any]) -> dict[str, Any]:
    summ = item.get("summary")
    return summ if isinstance(summ, dict) else {}


def _osv_id_list(summ: dict[str, Any], key: str) -> list[str]:
    raw = summ.get(key)
    if not isinstance(raw, list):
        return []
    return [str(x).strip() for x in raw if str(x).strip()]


def _format_osv_advisory_links(advisory_ids: list[str]) -> str:
    if not advisory_ids:
        return "—"
    parts: list[str] = []
    for aid in advisory_ids[:12]:
        encoded = aid.replace(")", "%29").replace("(", "%28")
        url = f"https://osv.dev/vulnerability/{encoded}"
        parts.append(f"[`{aid}`]({url})")
    if len(advisory_ids) > 12:
        parts.append(f"+{len(advisory_ids) - 12} more")
    return ", ".join(parts)


def _summary_table_row(item: dict[str, Any], *, bold_severity: bool = False) -> str:
    spec = str(item.get("package_spec") or "")
    eco = str(item.get("ecosystem") or "")
    worst = str(item.get("_worst_severity") or "")
    sev_cell = f"**{worst}**" if bold_severity else worst
    summ = _item_summary(item)
    ioc = "yes" if summ.get("ioc_hit") else "—"
    mal = str(summ.get("malware_risk") or "—")
    vuln = str(summ.get("vulnerability_risk") or "—")
    mal_ids = _osv_id_list(summ, "malicious_osv_ids")
    vuln_ids = _osv_id_list(summ, "vulnerable_osv_ids")
    advisories = _format_osv_advisory_links(mal_ids + vuln_ids)
    return f"| `{spec}` | {eco} | {sev_cell} | {ioc} | {mal} | {vuln} | {advisories} |"


def format_summary_markdown(
    rollup: dict[str, Any],
    *,
    blocked: list[dict[str, Any]],
    warned: list[dict[str, Any]],
    gate_summary: str,
    fail_on_cve: str = "none",
    workflow_findings: list[dict[str, Any]] | None = None,
) -> str:
    scan_id = str(rollup.get("bundle_id") or "")
    repo = str(rollup.get("source_repo") or "")
    ref = str(rollup.get("source_ref") or "")
    status = str(rollup.get("bundle_status") or "")
    scan_mode = str(rollup.get("scan_mode") or "runner-osv-ioc")
    discovery = str(rollup.get("discovery_mode") or "full")
    items = rollup.get("items") if isinstance(rollup.get("items"), list) else []
    wf = workflow_findings or []

    lines = [
        "<!-- chaintrap-sca -->",
        "## Chaintrap supply chain scan",
        "",
        f"- **Scan:** `{scan_id}`",
        f"- **Mode:** `{scan_mode}` (runner-local, no source upload)",
        f"- **Discovery:** `{discovery}`",
    ]
    if repo:
        lines.append(f"- **Repo:** `{repo}`")
    if ref:
        lines.append(f"- **Ref:** `{ref}`")
    lines.extend(
        [
            f"- **Status:** {status}",
            f"- **Gates:** `{gate_summary}`",
            f"- **Packages scanned:** {len(items)}",
            "",
        ]
    )

    if wf:
        lines.append(f"### Workflow hardening ({len(wf)})")
        lines.append("")
        lines.append("| Rule | Severity | File | Message |")
        lines.append("| --- | --- | --- | --- |")
        for f in wf:
            lines.append(
                f"| `{f.get('rule_id')}` | {f.get('severity')} | `{f.get('file')}` | {f.get('message')} |"
            )
        lines.append("")

    if blocked:
        lines.append(f"### Blocked ({len(blocked)})")
        lines.append("")
        lines.append(
            "| Package | Ecosystem | Severity | IOC | Malware | Vulnerability | Advisories |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for item in blocked:
            lines.append(_summary_table_row(item, bold_severity=True))
        lines.append("")

    if warned:
        lines.append(f"### Warnings ({len(warned)})")
        lines.append("")
        lines.append(
            "| Package | Ecosystem | Severity | IOC | Malware | Vulnerability | Advisories |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for item in warned:
            lines.append(_summary_table_row(item))
        lines.append("")

    partial = status == "partial"
    if partial:
        lines.append("### Scan errors (partial)")
        lines.append("")
        lines.append(
            "Some packages could not be fully checked (OSV/registry/content errors). "
            "Results may be incomplete — review before merging."
        )
        lines.append("")

    content_items = [
        item
        for item in items
        if isinstance(item, dict)
        and (_item_summary(item).get("content_findings") or _item_summary(item).get("osv_error"))
    ]
    if content_items:
        lines.append("### Content / scan errors")
        lines.append("")
        for item in content_items:
            spec = str(item.get("package_spec") or "")
            summ = _item_summary(item)
            if summ.get("osv_error"):
                lines.append(f"- `{spec}`: OSV error — {summ.get('osv_error')}")
            for hit in summ.get("content_findings") or []:
                if isinstance(hit, dict):
                    lines.append(
                        f"- `{spec}`: `{hit.get('rule_id')}` — {hit.get('message')}"
                    )
        lines.append("")

    if not blocked and not warned and not wf and not partial:
        lines.append("No supply-chain or workflow findings above benign.")
        lines.append("")

    return "\n".join(lines)


def gh_actions_error_annotation(item: dict[str, Any]) -> str:
    spec = str(item.get("package_spec") or "unknown")
    eco = str(item.get("ecosystem") or "")
    worst = str(item.get("_worst_severity") or "UNKNOWN")
    title = f"Chaintrap blocked {eco} package".strip()
    msg = f"{spec} — severity {worst}"
    return f"::error title={title}::{msg}"


def gh_actions_workflow_annotation(finding: dict[str, Any]) -> str:
    rule = str(finding.get("rule_id") or "CTW")
    sev = str(finding.get("severity") or "MEDIUM").upper()
    msg = str(finding.get("message") or rule)
    file = str(finding.get("file") or "")
    if sev in ("CRITICAL", "HIGH"):
        return f"::error file={file},line={finding.get('line', 1)}::{rule}: {msg}"
    return f"::warning file={file},line={finding.get('line', 1)}::{rule}: {msg}"


def _merge_policy(cfg: ScanConfig, policy: ChaintrapPolicy, args: argparse.Namespace) -> ScanConfig:
    if policy.minimum_release_age_days != 7:
        cfg.minimum_release_age_days = policy.minimum_release_age_days
    if policy.block_install_scripts:
        cfg.block_install_scripts = True
    if policy.block_typosquat:
        cfg.block_typosquat = True
    if policy.block_fresh_releases:
        cfg.block_fresh_releases = True
    cfg.ignored_packages |= policy.ignored_packages
    cfg.ignored_rules |= policy.ignored_rules
    if args.fail_on_cve == "none" and policy.fail_on_cve != "none":
        cfg.fail_on_cve = policy.fail_on_cve
    if not cfg.fail_on_error and policy.fail_on_error:
        cfg.fail_on_error = True
    if cfg.content_scan_enabled and not policy.content_scan:
        cfg.content_scan_enabled = False
    return cfg


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Chaintrap GitHub Actions runner-local SCA")
    p.add_argument("--repo", default=None)
    p.add_argument("--ref", default=None)
    p.add_argument("--paths", default="")
    p.add_argument("--ecosystems", default="npm,pypi")
    p.add_argument("--fail-on-ioc", default="block", choices=["block", "none"])
    p.add_argument("--fail-on-mal", default="true", choices=["true", "false"])
    p.add_argument("--fail-on-cve", default="none", choices=["critical", "high", "medium", "low", "none"])
    p.add_argument("--max-packages", type=int, default=200)
    p.add_argument("--workspace", default=".")
    p.add_argument("--action-root", default=None, help="Action repo root (vendor paths)")
    p.add_argument("--supabase-url", default="")
    p.add_argument("--supabase-key", default="")
    p.add_argument("--org-id", default="")
    p.add_argument("--api-url", default="")
    p.add_argument("--api-key", default="")
    p.add_argument("--sarif-output", default=None)
    p.add_argument("--summary-output", default=None)
    p.add_argument("--step-summary", default=None)
    p.add_argument("--diff-mode", default="false", choices=["true", "false"])
    p.add_argument("--base-ref", default="")
    p.add_argument("--heuristics", default="true", choices=["true", "false"])
    p.add_argument("--minimum-release-age", type=int, default=7)
    p.add_argument("--audit-workflows", default="true", choices=["true", "false"])
    p.add_argument("--block-workflow-critical", default="true", choices=["true", "false"])
    p.add_argument("--egress-allow", default="", help="Comma-separated extra egress allowlist domains")
    p.add_argument("--egress-block-unlisted", default="false", choices=["true", "false"])
    p.add_argument("--fail-on-error", default="false", choices=["true", "false"])
    p.add_argument("--content-scan", default="true", choices=["true", "false"])
    return p.parse_args(argv)


def run_scan(args: argparse.Namespace) -> int:
    global _ACTION_ROOT, _CI_SRC, _STATIC_SRC
    if args.action_root:
        _ACTION_ROOT = Path(args.action_root).resolve()
        _CI_SRC = _ACTION_ROOT / "vendor" / "chaintrap-ci" / "src"
        _STATIC_SRC = _ACTION_ROOT / "vendor" / "chaintrap-static-scan" / "src"

    workspace = Path(args.workspace).resolve()
    paths = [x.strip() for x in str(args.paths).split(",") if x.strip()] or None
    ecosystems = [x.strip().lower() for x in str(args.ecosystems).split(",") if x.strip()]

    policy = load_policy(workspace)
    cfg = ScanConfig(
        fail_on_ioc=str(args.fail_on_ioc),
        fail_on_mal=str(args.fail_on_mal).lower() == "true",
        fail_on_cve=str(args.fail_on_cve),
        max_packages=int(args.max_packages),
        diff_mode=str(args.diff_mode).lower() == "true",
        base_ref=str(args.base_ref or os.environ.get("GITHUB_BASE_REF") or "").strip(),
        heuristics_enabled=str(args.heuristics).lower() == "true",
        minimum_release_age_days=int(args.minimum_release_age),
        fail_on_error=str(args.fail_on_error).lower() == "true",
        content_scan_enabled=str(args.content_scan).lower() == "true",
    )
    cfg = _merge_policy(cfg, policy, args)

    supabase_url = str(args.supabase_url or os.environ.get("CHAINTRAP_SUPABASE_URL") or "").strip()
    supabase_key = str(args.supabase_key or os.environ.get("CHAINTRAP_IOC_READ_KEY") or "").strip()
    org_id = str(args.org_id or os.environ.get("CHAINTRAP_ORG_ID") or "").strip()

    if not (supabase_url and supabase_key and org_id):
        print("::notice::No Supabase IOC credentials — OSV-only mode (still blocks known MAL-*).")

    print("Running runner-local Chaintrap scan (osv.dev); source stays on the runner.")
    rollup = run_local_scan(
        workspace,
        repo=args.repo,
        ref=args.ref,
        paths=paths,
        ecosystems=ecosystems,
        max_packages=int(args.max_packages),
        supabase_url=supabase_url or None,
        supabase_key=supabase_key or None,
        org_id=org_id or None,
        cfg=cfg,
        data_dir=_ACTION_ROOT / "data",
    )

    workflow_findings: list[dict[str, Any]] = []
    audit_on = str(args.audit_workflows).lower() == "true" and policy.audit_workflows
    if audit_on:
        data_dir = _ACTION_ROOT / "data"
        cli_egress = [x.strip() for x in str(args.egress_allow).split(",") if x.strip()]
        egress_allow_combined = list(policy.egress_allow) + cli_egress
        egress_allow = frozenset(egress_allow_combined) if egress_allow_combined else None
        egress_block_unlisted = (
            policy.egress_block_unlisted
            or str(args.egress_block_unlisted).lower() == "true"
        )
        workflow_findings = audit_workflows(
            workspace,
            data_dir=data_dir if data_dir.is_dir() else None,
            egress_allow=egress_allow,
            egress_block_unlisted=egress_block_unlisted,
        )
        workflow_findings = [
            f for f in workflow_findings if str(f.get("rule_id") or "") not in cfg.ignored_rules
        ]
    rollup["workflow_findings"] = workflow_findings

    exit_code, blocked, warned = evaluate_scan_rollup(rollup, cfg)
    gate_summary = _gate_summary(cfg)

    block_wf_critical = str(args.block_workflow_critical).lower() == "true"
    if block_wf_critical:
        critical_wf = [
            f
            for f in workflow_findings
            if str(f.get("severity") or "").upper() in ("CRITICAL", "HIGH")
        ]
        if critical_wf and exit_code < 2:
            exit_code = 2

    summary_md = format_summary_markdown(
        rollup,
        blocked=blocked,
        warned=warned,
        gate_summary=gate_summary,
        fail_on_cve=cfg.fail_on_cve,
        workflow_findings=workflow_findings,
    )

    if args.sarif_output:
        sarif_path = Path(args.sarif_output)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(rollup_json_to_sarif(rollup), indent=2), encoding="utf-8")

    if args.summary_output:
        Path(args.summary_output).write_text(summary_md, encoding="utf-8")

    step_summary = args.step_summary or os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        Path(step_summary).write_text(summary_md + "\n", encoding="utf-8")

    for item in blocked:
        print(gh_actions_error_annotation(item))
    for f in workflow_findings:
        print(gh_actions_workflow_annotation(f))

    if exit_code == 2:
        print(f"Chaintrap: blocked ({gate_summary}).")
    elif exit_code == 1:
        print(f"Chaintrap: warnings only ({gate_summary}).")
    else:
        print("Chaintrap: pass.")

    # Report to Chaintrap API (fail-open, non-blocking)
    api_url = getattr(args, "api_url", "") or os.environ.get("CHAINTRAP_API_URL", "")
    api_key = getattr(args, "api_key", "") or os.environ.get("CHAINTRAP_API_KEY", "")
    if api_url and api_key:
        try:
            findings_payload = []
            for item in (rollup.get("findings") or []):
                findings_payload.append({
                    "ecosystem": item.get("ecosystem", "npm"),
                    "package_name": item.get("package", ""),
                    "package_version": item.get("version"),
                    "severity": (item.get("severity") or "UNKNOWN").upper(),
                    "category": item.get("category"),
                    "message": item.get("message"),
                })
            payload = {
                "org_id": args.org_id or os.environ.get("CHAINTRAP_ORG_ID", "default"),
                "repo_full_name": args.repo or os.environ.get("GITHUB_REPOSITORY", ""),
                "ref": args.ref or os.environ.get("GITHUB_REF_NAME", ""),
                "sha": os.environ.get("GITHUB_SHA", ""),
                "scan_id": "",
                "findings": findings_payload,
                "workflow_findings_count": len(workflow_findings),
            }
            import urllib.request
            import json as _json
            req = urllib.request.Request(
                f"{api_url.rstrip('/')}/api/v1/ci/report",
                data=_json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-API-Key": api_key},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                _ = resp.read()
        except Exception:
            # fail-open
            pass

    return exit_code


def main(argv: list[str] | None = None) -> int:
    try:
        return run_scan(parse_args(argv))
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
