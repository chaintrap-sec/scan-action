"""Rich GitHub PR summary markdown for Chaintrap CI scans."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from chaintrap_static_scan.signal_tiers import THEME_LABELS


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


def _block_reason(item: dict[str, Any]) -> str:
    summ = _item_summary(item)
    if summ.get("risk_tldr"):
        return str(summ["risk_tldr"])
    parts: list[str] = []
    if summ.get("ioc_hit"):
        src = summ.get("ioc_source") or "tenant IOC"
        parts.append(f"Tenant IOC match ({src})")
    mal_ids = _osv_id_list(summ, "malicious_osv_ids")
    if mal_ids:
        parts.append(f"OSV malicious advisory: {', '.join(mal_ids[:3])}")
    if summ.get("known_bad_hit"):
        parts.append("Known-bad denylist match")
    return "; ".join(parts) or "Policy gate triggered"


def _format_package_risk_card(item: dict[str, Any]) -> list[str]:
    spec = str(item.get("package_spec") or "unknown")
    summ = _item_summary(item)
    verdict = str(summ.get("verdict_level") or "PASS")
    score = summ.get("risk_score")
    score_txt = f"{score}/10" if isinstance(score, (int, float)) else "—"
    lines = [f"### `{spec}` — {verdict} · {score_txt}", ""]
    declared = item.get("declared_constraint")
    resolution_source = str(item.get("resolution_source") or "")
    if declared and resolution_source == "compile":
        lines.append(
            f"**Resolved:** `{declared}` → `{spec}` (compiled)"
        )
        lines.append("")
    elif resolution_source == "compile":
        lines.append(f"**Resolved:** `{spec}` (compiled manifest)")
        lines.append("")
    tldr = summ.get("risk_tldr") or _block_reason(item)
    lines.append(f"**TL;DR:** {tldr}")
    lines.append("")
    themes = summ.get("risk_themes") if isinstance(summ.get("risk_themes"), dict) else {}
    if themes:
        lines.append("| Threat theme | Result |")
        lines.append("| --- | --- |")
        for key, label in THEME_LABELS.items():
            entry = themes.get(key) or {}
            lines.append(f"| {label} | {entry.get('label', '—')} |")
        lines.append("")
    evidence = summ.get("top_evidence") if isinstance(summ.get("top_evidence"), list) else []
    suppressed = int(summ.get("suppressed_count") or 0)
    if evidence:
        lines.append("<details>")
        lines.append(
            f"<summary>Evidence ({len(evidence)} shown"
            + (f", {suppressed} low-signal hits hidden" if suppressed else "")
            + ")</summary>"
        )
        lines.append("")
        for hit in evidence:
            if not isinstance(hit, dict):
                continue
            rid = hit.get("rule_id", "")
            fpath = hit.get("file", "")
            line_no = hit.get("line", "")
            count = hit.get("count", 1)
            snippet = str(hit.get("snippet") or "")[:120]
            loc = f"`{fpath}:{line_no}`" if fpath else ""
            cnt = f" ×{count}" if int(count or 1) > 1 else ""
            lines.append(f"- `{rid}`{cnt} {loc} — {snippet}")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    if summ.get("content_scan_error"):
        lines.append(f"> Static analysis error: {summ['content_scan_error']}")
        lines.append("")
    lines.append(
        "**If intentional:** add `.chaintrap.yml` ignore (reason + expiry) "
        "or request an org waiver in the DepShield dashboard."
    )
    lines.append("")
    return lines


def _remediation_hint(item: dict[str, Any]) -> str:
    summ = _item_summary(item)
    spec = str(item.get("package_spec") or "")
    name = spec.rsplit("@", 1)[0] if "@" in spec else spec
    if summ.get("malicious_osv_ids") or summ.get("ioc_hit"):
        return f"Remove `{name}` and rotate any credentials that may have been exposed."
    vuln_ids = _osv_id_list(summ, "vulnerable_osv_ids")
    if vuln_ids:
        return f"Upgrade `{name}` to a patched version; check OSV for fixed releases."
    return "Review dependency necessity and update lockfile."


def _items_with_vulnerable_osv(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in items if _osv_id_list(_item_summary(item), "vulnerable_osv_ids")]


def _group_by_ecosystem(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        eco = str(item.get("ecosystem") or "unknown")
        grouped.setdefault(eco, []).append(item)
    return grouped


def format_summary_markdown(
    rollup: dict[str, Any],
    *,
    blocked: list[dict[str, Any]],
    warned: list[dict[str, Any]],
    gate_summary: str,
    fail_on_cve: str = "none",
    workflow_findings: list[dict[str, Any]] | None = None,
    dashboard_url: str | None = None,
    org_id: str | None = None,
) -> str:
    scan_id = str(rollup.get("bundle_id") or "")
    repo = str(rollup.get("source_repo") or "")
    ref = str(rollup.get("source_ref") or "")
    status = str(rollup.get("bundle_status") or "")
    scan_mode = str(rollup.get("scan_mode") or "runner-osv-ioc")
    discovery = str(rollup.get("discovery_mode") or "full")
    resolution_warnings = (
        rollup.get("resolution_warnings")
        if isinstance(rollup.get("resolution_warnings"), list)
        else []
    )
    items = rollup.get("items") if isinstance(rollup.get("items"), list) else []
    wf = workflow_findings or []

    blocked_count = len(blocked)
    warned_count = len(warned)
    status_banner = "✅ **Pass**" if not blocked_count and not warned_count else (
        "🚫 **Blocked**" if blocked_count else "⚠️ **Warnings**"
    )

    lines = [
        "<!-- chaintrap-sca -->",
        "## Chaintrap supply chain scan",
        "",
        status_banner,
        "",
        "> 🔒 **Privacy mode** — scan runs on your GitHub runner; lockfile contents are not uploaded.",
        "",
        f"| Metric | Value |",
        f"| --- | --- |",
        f"| Scan ID | `{scan_id}` |",
        f"| Mode | `{scan_mode}` |",
        f"| Discovery | `{discovery}` |",
        f"| Status | {status} |",
        f"| Gates | `{gate_summary}` |",
        f"| Packages scanned | {len(items)} |",
        f"| Blocked | {blocked_count} |",
        f"| Warnings | {warned_count} |",
    ]
    if repo:
        lines.append(f"| Repo | `{repo}` |")
    if ref:
        lines.append(f"| Ref | `{ref}` |")
    lines.append("")

    if resolution_warnings:
        lines.append("<details>")
        lines.append(
            f"<summary><strong>Unpinned manifests compiled ({len(resolution_warnings)} warning(s))</strong></summary>"
        )
        lines.append("")
        for warn in resolution_warnings:
            if not isinstance(warn, dict):
                continue
            manifest = warn.get("manifest") or "manifest"
            err = warn.get("error") or "unknown error"
            lines.append(f"- `{manifest}`: {err}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if wf:
        lines.append("<details>")
        lines.append(f"<summary><strong>Workflow hardening ({len(wf)})</strong></summary>")
        lines.append("")
        lines.append("| Rule | Severity | File | Message |")
        lines.append("| --- | --- | --- | --- |")
        for f in wf:
            lines.append(
                f"| `{f.get('rule_id')}` | {f.get('severity')} | `{f.get('file')}` | {f.get('message')} |"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

    vuln_warn_only = (fail_on_cve or "none").strip().lower() == "none"
    vuln_items = _items_with_vulnerable_osv(blocked + warned)
    if vuln_items:
        lines.append("<details>")
        lines.append(f"<summary><strong>OSV vulnerability advisories ({len(vuln_items)})</strong></summary>")
        lines.append("")
        if vuln_warn_only:
            lines.append(
                "> Known CVE/GHSA advisories from [osv.dev](https://osv.dev). "
                "Warnings only while `fail-on-cve: none`."
            )
            lines.append("")
        for eco, eco_items in sorted(_group_by_ecosystem(vuln_items).items()):
            lines.append(f"#### {eco}")
            lines.append("")
            lines.append("| Package | OSV advisories |")
            lines.append("| --- | --- |")
            for item in eco_items:
                spec = str(item.get("package_spec") or "")
                advisories = _format_osv_advisory_links(_osv_id_list(_item_summary(item), "vulnerable_osv_ids"))
                lines.append(f"| `{spec}` | {advisories} |")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    if blocked:
        lines.append("<details open>")
        lines.append(f"<summary><strong>Blocked packages ({len(blocked)})</strong></summary>")
        lines.append("")
        for item in blocked:
            lines.extend(_format_package_risk_card(item))
            lines.append(f"- **Remediation:** {_remediation_hint(item)}")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    other_warned = [
        item
        for item in warned
        if not _osv_id_list(_item_summary(item), "vulnerable_osv_ids")
    ]
    if other_warned:
        lines.append("<details>")
        lines.append(f"<summary><strong>Review recommended ({len(other_warned)})</strong></summary>")
        lines.append("")
        for item in other_warned:
            lines.extend(_format_package_risk_card(item))
        lines.append("</details>")
        lines.append("")

    partial = status == "partial"
    if partial:
        lines.append("> ⚠️ Some packages could not be fully checked (OSV/registry/content errors).")
        lines.append("")

    if not blocked and not warned and not wf and not partial:
        lines.append("No supply-chain or workflow findings above benign.")
        lines.append("")

    lines.append("---")
    lines.append("*Powered by [Chaintrap](https://chaintrap.com)*")
    return "\n".join(lines)
