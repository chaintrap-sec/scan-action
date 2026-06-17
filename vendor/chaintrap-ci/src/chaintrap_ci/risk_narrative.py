"""Developer-facing risk summary from content findings and OSV/IOC signals."""

from __future__ import annotations

from typing import Any

from chaintrap_static_scan.signal_tiers import (
    THEME_LABELS,
    infer_signal_tier,
    theme_for_rule,
)

_SEV_WEIGHT = {"critical": 4.0, "high": 2.0, "medium": 1.0, "low": 0.35, "info": 0.1}
_TIER_WEIGHT = {"block": 4.0, "review": 1.5, "info": 0.1}
_MAX_EVIDENCE = 5


def _norm_hit(hit: dict[str, Any]) -> dict[str, Any]:
    out = {
        "rule_id": str(hit.get("rule_id") or ""),
        "severity": str(hit.get("severity") or "LOW").upper(),
        "category": str(hit.get("category") or ""),
        "message": str(hit.get("message") or ""),
        "file": str(hit.get("file") or ""),
        "line": int(hit.get("line") or 0),
        "snippet": str(hit.get("snippet") or "")[:240],
    }
    artifacts = hit.get("artifacts")
    if isinstance(artifacts, dict):
        out["artifacts"] = artifacts
    return out


def dedupe_content_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """
    Group by rule_id; keep best representative (highest tier, first file:line).
    Returns (deduped_groups, total_raw_count).
    """
    raw_count = len(findings)
    buckets: dict[str, dict[str, Any]] = {}
    for raw in findings:
        if not isinstance(raw, dict):
            continue
        hit = _norm_hit(raw)
        rid = hit["rule_id"]
        if not rid:
            continue
        tier = infer_signal_tier(rid, hit["severity"], hit["category"])
        hit["signal_tier"] = tier
        hit["theme"] = theme_for_rule(rid, hit["category"])
        existing = buckets.get(rid)
        if existing is None:
            buckets[rid] = {**hit, "count": 1}
            continue
        existing["count"] = int(existing.get("count") or 0) + 1
        tier_rank = {"block": 3, "review": 2, "info": 1}
        if tier_rank.get(tier, 0) > tier_rank.get(existing.get("signal_tier"), 0):
            for k in ("file", "line", "snippet", "severity", "signal_tier", "theme", "message", "artifacts"):
                if k in hit:
                    existing[k] = hit[k]
    groups = sorted(
        buckets.values(),
        key=lambda h: (
            {"block": 0, "review": 1, "info": 2}.get(str(h.get("signal_tier")), 9),
            -_SEV_WEIGHT.get(str(h.get("severity", "")).lower(), 0),
            str(h.get("rule_id")),
        ),
    )
    return groups, raw_count


def _theme_status(theme: str, hits: list[dict[str, Any]]) -> dict[str, Any]:
    theme_hits = [h for h in hits if h.get("theme") == theme]
    if not theme_hits:
        return {"status": "not_detected", "rules": [], "count": 0, "label": "Not detected"}
    block_or_review = [h for h in theme_hits if h.get("signal_tier") in ("block", "review")]
    if block_or_review:
        rules = [f"`{h['rule_id']}` ({h.get('count', 1)})" for h in block_or_review[:6]]
        return {
            "status": "found",
            "rules": rules,
            "count": sum(int(h.get("count") or 1) for h in block_or_review),
            "label": f"**Found** — {', '.join(rules)}",
        }
    weak = theme_hits[0]
    return {
        "status": "weak_signal",
        "rules": [weak["rule_id"]],
        "count": int(weak.get("count") or 1),
        "label": f"Weak signal (`{weak['rule_id']}`)",
    }


def compute_risk_score(
    *,
    deduped_hits: list[dict[str, Any]],
    has_mal_osv: bool = False,
    has_ioc: bool = False,
    has_known_bad: bool = False,
) -> float:
    if has_mal_osv or has_ioc or has_known_bad:
        return 10.0
    points = 0.0
    seen_tiers: set[str] = set()
    for h in deduped_hits:
        tier = str(h.get("signal_tier") or infer_signal_tier(h["rule_id"], h["severity"], h["category"]))
        if tier == "info":
            continue
        rid = h["rule_id"]
        if rid in seen_tiers:
            continue
        seen_tiers.add(rid)
        sev = str(h.get("severity") or "").lower()
        points += _TIER_WEIGHT.get(tier, 0.5) + _SEV_WEIGHT.get(sev, 0.1) * 0.25
    return min(10.0, round(points, 1))


def derive_verdict_from_content(
    *,
    score: float,
    deduped_hits: list[dict[str, Any]],
    has_mal_osv: bool,
    has_ioc: bool,
    has_known_bad: bool,
) -> str:
    if has_mal_osv or has_ioc or has_known_bad:
        return "BLOCK"
    if any(h.get("signal_tier") == "block" for h in deduped_hits):
        return "BLOCK"
    review_hits = [h for h in deduped_hits if h.get("signal_tier") == "review"]
    themes_found = {h.get("theme") for h in review_hits if h.get("theme")}
    has_shell = "shell_execution" in themes_found
    has_network = "suspicious_network" in themes_found
    if score >= 7.0 or len(themes_found) >= 2:
        return "REVIEW"
    if score >= 4.5 and has_shell and has_network:
        return "REVIEW"
    if score >= 4.5 or review_hits:
        return "WARN"
    if score >= 1.5:
        return "INFO"
    return "PASS"


def build_risk_tldr(
    *,
    deduped_hits: list[dict[str, Any]],
    themes: dict[str, dict[str, Any]],
    has_mal_osv: bool,
    has_ioc: bool,
    malicious_osv_ids: list[str],
) -> str:
    if has_mal_osv or has_ioc:
        ids = ", ".join(malicious_osv_ids[:3]) if malicious_osv_ids else "intel match"
        return f"Known malicious package ({ids}). Remove immediately and rotate exposed credentials."

    parts: list[str] = []
    shell = themes.get("shell_execution", {})
    if shell.get("status") == "found":
        parts.append("Shell command execution and subprocess usage detected")
    elif shell.get("status") == "weak_signal":
        parts.append("Possible shell/process patterns")

    obf = themes.get("obfuscation", {})
    if obf.get("status") == "found":
        parts.append("obfuscated or packed code patterns")
    elif obf.get("status") == "weak_signal":
        parts.append("weak obfuscation signals (e.g. base64 decode)")

    install = themes.get("install_time_risk", {})
    if install.get("status") == "found":
        parts.append("install-time fetch-and-run or hook risk")

    exfil = themes.get("data_exfiltration", {})
    cred = themes.get("credential_access", {})

    if not parts:
        parts.append("Low-signal static patterns only")

    lead = "; ".join(parts).rstrip(".") + "."

    negatives: list[str] = []
    if cred.get("status") == "not_detected":
        negatives.append("credential-stealer patterns")
    if exfil.get("status") == "not_detected":
        negatives.append("known exfil URLs")
    if install.get("status") == "not_detected":
        negatives.append("install-time fetch-and-run")

    if negatives:
        lead += f" No {' or '.join(negatives)} detected."
    else:
        lead += " Manual review recommended."

    return lead


def enrich_summary_with_risk_narrative(
    summary: dict[str, Any],
    content_findings: list[dict[str, Any]] | None,
    *,
    known_bad: bool = False,
) -> dict[str, Any]:
    """Merge content findings into summary with TL;DR, score, themes."""
    out = dict(summary)
    raw = list(content_findings or [])
    out["content_findings"] = raw
    deduped, raw_count = dedupe_content_findings(raw)
    out["content_findings_deduped"] = deduped
    out["content_findings_raw_count"] = raw_count
    out["suppressed_count"] = max(0, raw_count - len([h for h in deduped if h.get("signal_tier") != "info"]))

    has_mal = bool(out.get("malicious_osv_ids"))
    has_ioc = bool(out.get("ioc_hit"))
    score = compute_risk_score(
        deduped_hits=deduped,
        has_mal_osv=has_mal,
        has_ioc=has_ioc,
        has_known_bad=known_bad,
    )
    out["risk_score"] = score

    theme_keys = list(THEME_LABELS.keys())
    themes: dict[str, dict[str, Any]] = {}
    for key in theme_keys:
        if key == "known_malware":
            if has_mal or has_ioc or known_bad:
                themes[key] = {"status": "found", "label": "**Found**", "rules": [], "count": 1}
            else:
                themes[key] = {"status": "not_detected", "label": "None", "rules": [], "count": 0}
        else:
            themes[key] = _theme_status(key, deduped)
    out["risk_themes"] = themes

    if has_mal or has_ioc or known_bad:
        verdict = "BLOCK"
        out["malware_risk"] = "CRITICAL"
    else:
        verdict = derive_verdict_from_content(
            score=score,
            deduped_hits=deduped,
            has_mal_osv=has_mal,
            has_ioc=has_ioc,
            has_known_bad=known_bad,
        )
        if verdict in ("BLOCK", "REVIEW") and out.get("malware_risk") in (None, "NONE", "—"):
            out["malware_risk"] = "HIGH" if verdict == "REVIEW" else "CRITICAL"

    existing = str(out.get("verdict_level") or "PASS")
    rank = {"PASS": 0, "INFO": 1, "WARN": 2, "REVIEW": 3, "BLOCK": 4}
    if rank.get(verdict, 0) > rank.get(existing, 0):
        out["verdict_level"] = verdict
    elif has_mal or has_ioc:
        out["verdict_level"] = "BLOCK"

    visible = [h for h in deduped if h.get("signal_tier") in ("block", "review")]
    info_hidden = [h for h in deduped if h.get("signal_tier") == "info"]
    out["top_evidence"] = visible[:_MAX_EVIDENCE]
    out["suppressed_count"] = raw_count - len(visible) + sum(
        max(0, int(h.get("count") or 1) - 1) for h in visible
    )
    if info_hidden:
        out["suppressed_count"] += sum(int(h.get("count") or 1) for h in info_hidden)

    out["risk_tldr"] = build_risk_tldr(
        deduped_hits=deduped,
        themes=themes,
        has_mal_osv=has_mal,
        has_ioc=has_ioc,
        malicious_osv_ids=list(out.get("malicious_osv_ids") or []),
    )
    return out


def has_block_tier_content(summary: dict[str, Any]) -> bool:
    deduped = summary.get("content_findings_deduped")
    if not deduped:
        raw = [h for h in (summary.get("content_findings") or []) if isinstance(h, dict)]
        if raw:
            deduped, _ = dedupe_content_findings(raw)
        else:
            deduped = []
    return any(isinstance(h, dict) and h.get("signal_tier") == "block" for h in deduped)
