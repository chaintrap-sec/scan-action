"""Runner-local OSV + Supabase IOC + heuristics scan for GitHub Actions."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chaintrap_static_scan.content_scan import scan_packages_content
from chaintrap_static_scan.heuristics import run_heuristics_batch
from chaintrap_static_scan.models import OsvFinding, PackageKey
from chaintrap_static_scan.pipeline import scan_packages

from chaintrap_ci.discover import discover
from chaintrap_ci.discover_diff import discover_added_packages
from chaintrap_ci.ioc_client import fetch_org_iocs
from chaintrap_ci.parse import ioc_lookup_key, split_package_spec

_CI_HOST = "github-actions"

_SEV_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "MODERATE": 2,
    "LOW": 1,
    "NONE": 0,
    "UNKNOWN": 0,
}


@dataclass
class ScanConfig:
    fail_on_ioc: str = "block"  # block | none
    fail_on_mal: bool = True
    fail_on_cve: str = "none"  # none | critical | high | medium | low
    max_packages: int = 200
    diff_mode: bool = False
    base_ref: str = ""
    heuristics_enabled: bool = True
    minimum_release_age_days: int = 7
    block_install_scripts: bool = False
    block_typosquat: bool = False
    block_fresh_releases: bool = False
    fail_on_error: bool = False
    content_scan_enabled: bool = True
    content_scan_max_packages: int = 30
    ignored_packages: set[str] = field(default_factory=set)
    ignored_rules: set[str] = field(default_factory=set)


def _fail_rank(level: str) -> int:
    key = (level or "high").strip().lower()
    if key == "none":
        return 999
    return _SEV_RANK.get(key.upper(), _SEV_RANK["HIGH"])


def _heuristic_severity_to_rank(sev: str) -> int:
    return _SEV_RANK.get(str(sev or "LOW").upper(), 1)


def _content_severity_rank(sev: str) -> int:
    return _SEV_RANK.get(str(sev or "LOW").upper(), 1)


def _summary_for_item(
    *,
    ecosystem: str,
    package_spec: str,
    finding: OsvFinding,
    ioc_row: dict[str, Any] | None,
    heuristic_hits: list[dict[str, Any]] | None = None,
    content_hits: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    mal = list(finding.malicious_ids or [])
    vuln = list(finding.vulnerable_ids or [])
    ioc_hit = ioc_row is not None
    heur = list(heuristic_hits or [])
    content = list(content_hits or [])

    if finding.query_error:
        return {
            "verdict_level": "WARN",
            "malware_risk": "—",
            "vulnerability_risk": "—",
            "osv_error": finding.query_error,
            "ioc_hit": False,
            "heuristic_findings": heur,
            "content_findings": content,
        }

    malware_risk = "NONE"
    vulnerability_risk = "NONE"
    verdict_level = "PASS"

    if ioc_hit:
        sev = str(ioc_row.get("severity") or "CRITICAL").strip().upper()
        malware_risk = sev if sev in _SEV_RANK else "CRITICAL"
        verdict_level = "BLOCK"
    elif mal:
        malware_risk = "CRITICAL"
        verdict_level = "BLOCK"
    elif vuln:
        vulnerability_risk = "HIGH"
        verdict_level = "REVIEW"
    elif content:
        worst_c = max(content, key=lambda h: _content_severity_rank(str(h.get("severity"))))
        cs = str(worst_c.get("severity") or "LOW").upper()
        if cs in ("CRITICAL", "HIGH"):
            verdict_level = "BLOCK"
            malware_risk = cs if cs in _SEV_RANK else "CRITICAL"
        elif cs == "MEDIUM":
            verdict_level = "REVIEW"
        else:
            verdict_level = "WARN"
    elif heur:
        worst_h = max(heur, key=lambda h: _heuristic_severity_to_rank(str(h.get("severity"))))
        hs = str(worst_h.get("severity") or "LOW").upper()
        if hs in ("CRITICAL", "HIGH"):
            verdict_level = "BLOCK"
        elif hs == "MEDIUM":
            verdict_level = "REVIEW"
        else:
            verdict_level = "WARN"

    summary: dict[str, Any] = {
        "verdict_level": verdict_level,
        "malware_risk": malware_risk,
        "vulnerability_risk": vulnerability_risk,
        "ioc_hit": ioc_hit,
        "malicious_osv_ids": mal,
        "vulnerable_osv_ids": vuln,
        "heuristic_findings": heur,
        "content_findings": content,
    }
    if ioc_hit:
        summary["ioc_severity"] = str(ioc_row.get("severity") or "CRITICAL")
        summary["ioc_source"] = str(ioc_row.get("source") or "")
        summary["ioc_key"] = str(ioc_row.get("ioc_key") or "")
    return summary


def _item_worst_severity(item: dict[str, Any]) -> str:
    summ = item.get("summary") if isinstance(item.get("summary"), dict) else {}
    labels: list[str] = []
    if summ.get("ioc_hit"):
        labels.append(str(summ.get("ioc_severity") or summ.get("malware_risk") or "CRITICAL"))
    for key in ("malware_risk", "vulnerability_risk", "verdict_level"):
        val = summ.get(key)
        if val is not None and str(val).strip() and str(val).strip() != "—":
            labels.append(str(val))
    for hit in summ.get("heuristic_findings") or []:
        if isinstance(hit, dict):
            labels.append(str(hit.get("severity") or "LOW"))
    for hit in summ.get("content_findings") or []:
        if isinstance(hit, dict):
            labels.append(str(hit.get("severity") or "LOW"))
    best = "NONE"
    best_r = -1
    for raw in labels:
        u = str(raw).strip().upper()
        if u == "MODERATE":
            u = "MEDIUM"
        if u == "BLOCK":
            u = "CRITICAL"
        if u == "REVIEW":
            u = "HIGH"
        if u == "WARN":
            u = "MEDIUM"
        if u == "PASS":
            u = "NONE"
        r = _SEV_RANK.get(u, -1)
        if r > best_r:
            best_r = r
            best = u
    return best if best_r >= 0 else "UNKNOWN"


def _should_block_content(hit: dict[str, Any], cfg: ScanConfig) -> bool:
    rule = str(hit.get("rule_id") or "")
    if rule in cfg.ignored_rules:
        return False
    sev = str(hit.get("severity") or "LOW").upper()
    return sev in ("CRITICAL", "HIGH")


def _should_block_heuristic(hit: dict[str, Any], cfg: ScanConfig) -> bool:
    rule = str(hit.get("rule_id") or "")
    if rule in cfg.ignored_rules:
        return False
    sev = str(hit.get("severity") or "LOW").upper()
    if rule == "CTH-001" and cfg.block_fresh_releases:
        return True
    if rule == "CTH-002" and cfg.block_install_scripts:
        return True
    if rule == "CTH-003" and cfg.block_typosquat:
        return True
    return False


def evaluate_scan_rollup(
    rollup: dict[str, Any],
    cfg: ScanConfig,
) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (exit_code, blocked, warned). exit 0 pass, 1 warn-only, 2 blocked."""
    items = rollup.get("items") if isinstance(rollup.get("items"), list) else []
    ioc_blocks = (cfg.fail_on_ioc or "block").strip().lower() != "none"
    cve_threshold = _fail_rank(cfg.fail_on_cve)

    blocked: list[dict[str, Any]] = []
    warned: list[dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        spec = str(item.get("package_spec") or "")
        if spec.lower() in cfg.ignored_packages:
            continue
        summ = item.get("summary") if isinstance(item.get("summary"), dict) else {}
        worst = _item_worst_severity(item)
        rank = _SEV_RANK.get(worst, 0)
        enriched = dict(item)
        enriched["_worst_severity"] = worst
        enriched["_severity_rank"] = rank

        is_blocked = False
        if summ.get("ioc_hit") and ioc_blocks:
            is_blocked = True
        elif cfg.fail_on_mal and summ.get("malicious_osv_ids"):
            is_blocked = True
        elif summ.get("vulnerable_osv_ids") and rank >= cve_threshold and cve_threshold < 999:
            is_blocked = True
        else:
            for hit in summ.get("content_findings") or []:
                if isinstance(hit, dict) and _should_block_content(hit, cfg):
                    is_blocked = True
                    break
            if not is_blocked:
                for hit in summ.get("heuristic_findings") or []:
                    if isinstance(hit, dict) and _should_block_heuristic(hit, cfg):
                        is_blocked = True
                        break

        if is_blocked:
            blocked.append(enriched)
        elif rank > 0:
            warned.append(enriched)

    bundle_status = str(rollup.get("bundle_status") or "")
    if cfg.fail_on_error and bundle_status == "partial":
        return 2, blocked, warned

    if blocked:
        return 2, blocked, warned
    if warned:
        return 1, blocked, warned
    return 0, blocked, warned


def run_local_scan(
    workspace: Path,
    *,
    repo: str | None = None,
    ref: str | None = None,
    paths: list[str] | None = None,
    ecosystems: list[str] | None = None,
    max_packages: int = 200,
    supabase_url: str | None = None,
    supabase_key: str | None = None,
    org_id: str | None = None,
    cfg: ScanConfig | None = None,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    """Discover lockfiles, OSV scan on runner, optional Supabase IOC + heuristics."""
    cfg = cfg or ScanConfig(max_packages=max_packages)
    cfg.max_packages = max_packages

    eco_list = ecosystems or ["npm", "pypi"]
    eco_set = {e.strip().lower() for e in eco_list if e.strip()}
    discovery_mode = "full"

    if cfg.diff_mode and cfg.base_ref:
        discovered, discovery_mode = discover_added_packages(
            workspace,
            base_ref=cfg.base_ref,
            ecosystems=eco_set,
            paths=paths,
            max_items=max_packages,
        )
    else:
        discovered = discover(
            workspace=workspace,
            paths=paths,
            ecosystems=eco_list,
            max_packages=max_packages,
        )

    if not discovered:
        raise ValueError("No packages discovered; nothing to scan.")

    keys: list[PackageKey] = []
    parsed_items: list[dict[str, str]] = []
    for row in discovered:
        eco = str(row.get("ecosystem") or "").strip().lower()
        spec = str(row.get("package_spec") or "").strip()
        if not eco or not spec:
            continue
        name, ver = split_package_spec(eco, spec)
        keys.append(PackageKey(host=_CI_HOST, ecosystem=eco, name=name, version=ver))  # type: ignore[arg-type]
        parsed_items.append({"ecosystem": eco, "package_spec": spec, "name": name, "version": ver})

    osv_findings = scan_packages(keys)

    ioc_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    if supabase_url and supabase_key and org_id:
        ioc_map = fetch_org_iocs(supabase_url, supabase_key, org_id)

    heur_map: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    if cfg.heuristics_enabled:
        pkg_tuples = [(r["ecosystem"], r["name"], r["version"]) for r in parsed_items]
        heur_map = run_heuristics_batch(
            pkg_tuples,
            minimum_release_age_days=cfg.minimum_release_age_days,
            data_dir=data_dir,
        )

    content_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    if cfg.content_scan_enabled and cfg.diff_mode:
        pkg_tuples = [(r["ecosystem"], r["name"], r["version"]) for r in parsed_items]
        content_map = scan_packages_content(
            pkg_tuples,
            max_packages=cfg.content_scan_max_packages,
        )

    rollup_items: list[dict[str, Any]] = []
    any_err = False
    for row, pk in zip(parsed_items, keys):
        finding = osv_findings.get(pk) or OsvFinding(malicious_ids=[], vulnerable_ids=[], query_error="no result")
        lookup = ioc_lookup_key(row["ecosystem"], row["name"], row["version"])
        ioc_row = ioc_map.get(lookup)
        pkg_key = (row["ecosystem"], row["name"], row["version"])
        heur = [
            h
            for h in heur_map.get(pkg_key, [])
            if str(h.get("rule_id") or "") not in cfg.ignored_rules
        ]
        content_entry = content_map.get(pkg_key, {})
        content_hits = [
            h
            for h in (content_entry.get("findings") or [])
            if isinstance(h, dict) and str(h.get("rule_id") or "") not in cfg.ignored_rules
        ]
        if content_entry.get("error"):
            any_err = True
        if finding.query_error:
            any_err = True
            status = "error"
        else:
            status = "complete"
        rollup_items.append(
            {
                "ecosystem": row["ecosystem"],
                "package_spec": row["package_spec"],
                "item_status": status,
                "summary": _summary_for_item(
                    ecosystem=row["ecosystem"],
                    package_spec=row["package_spec"],
                    finding=finding,
                    ioc_row=ioc_row,
                    heuristic_hits=heur,
                    content_hits=content_hits,
                ),
            }
        )

    scan_mode = f"runner-osv-ioc-{discovery_mode}"
    if cfg.content_scan_enabled and cfg.diff_mode:
        scan_mode += "-content"

    return {
        "schema_version": 1,
        "scan_mode": scan_mode,
        "bundle_id": str(uuid.uuid4()),
        "source_repo": repo,
        "source_ref": ref,
        "bundle_status": "partial" if any_err else "complete",
        "items": rollup_items,
        "ioc_enabled": bool(ioc_map or (supabase_url and supabase_key and org_id)),
        "package_count": len(rollup_items),
        "discovery_mode": discovery_mode,
    }
