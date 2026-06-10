"""Convert dependency + workflow findings to SARIF 2.1.0."""

from __future__ import annotations

from typing import Any

_SEV_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "MODERATE": 2,
    "LOW": 1,
    "NONE": 0,
    "UNKNOWN": 0,
    "INFO": 0,
    "BENIGN": 0,
    "PASS": 0,
    "MINIMAL": 0,
}

_VERDICT_MAP = {
    "BLOCK": "CRITICAL",
    "REVIEW": "HIGH",
    "WARN": "MEDIUM",
    "INFO": "LOW",
    "PASS": "NONE",
}


def _norm_severity(raw: str) -> str:
    u = (raw or "").strip().upper()
    if u == "MODERATE":
        return "MEDIUM"
    mapped = _VERDICT_MAP.get(u)
    if mapped:
        return mapped
    return u or "UNKNOWN"


def _sarif_level(severity: str) -> str:
    u = _norm_severity(severity)
    if u in ("CRITICAL", "HIGH"):
        return "error"
    if u == "MEDIUM":
        return "warning"
    if u == "LOW":
        return "note"
    return "none"


def _ensure_rule(rules_seen: dict[str, dict], rule_id: str, name: str, desc: str) -> None:
    if rule_id not in rules_seen:
        rules_seen[rule_id] = {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": desc},
        }


def rollup_json_to_sarif(rollup: dict[str, Any]) -> dict[str, Any]:
    items = rollup.get("items") if isinstance(rollup.get("items"), list) else []
    wf_findings = rollup.get("workflow_findings")
    if not isinstance(wf_findings, list):
        wf_findings = []

    bundle_id = str(rollup.get("bundle_id") or "")
    source_repo = str(rollup.get("source_repo") or "")
    source_ref = str(rollup.get("source_ref") or "")

    rules_seen: dict[str, dict[str, str]] = {}
    results: list[dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        spec = str(item.get("package_spec") or "unknown")
        eco = str(item.get("ecosystem") or "")
        summ = item.get("summary") if isinstance(item.get("summary"), dict) else {}
        lockfile = str(item.get("lockfile") or "")
        line = int(item.get("lockfile_line") or 1)

        for mal_id in summ.get("malicious_osv_ids") or []:
            rule_id = "chaintrap/malware"
            _ensure_rule(rules_seen, rule_id, "Malicious package", "OSV MAL-* advisory")
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error",
                    "message": {"text": f"{spec}: {mal_id}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": lockfile or spec},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                    "properties": {"ecosystem": eco, "package_spec": spec, "osv_id": mal_id},
                }
            )

        if summ.get("known_bad_hit"):
            kb = summ.get("known_bad_finding") if isinstance(summ.get("known_bad_finding"), dict) else {}
            rule_id = str(kb.get("rule_id") or "chaintrap/known-bad")
            _ensure_rule(rules_seen, rule_id, "Known-bad package", "OSV-independent denylist match")
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error",
                    "message": {"text": f"{spec}: {kb.get('message') or 'known-bad denylist'}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": lockfile or spec},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                    "properties": {"ecosystem": eco, "package_spec": spec, "campaign": kb.get("campaign")},
                }
            )

        if summ.get("ioc_hit"):
            rule_id = "chaintrap/ioc"
            _ensure_rule(rules_seen, rule_id, "Tenant IOC match", "Supabase package IOC indicator")
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error",
                    "message": {"text": f"{spec}: IOC match"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": lockfile or spec},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                    "properties": {"ecosystem": eco, "package_spec": spec},
                }
            )

        for hit in summ.get("heuristic_findings") or []:
            if not isinstance(hit, dict):
                continue
            rule_id = str(hit.get("rule_id") or "chaintrap/heuristic")
            _ensure_rule(rules_seen, rule_id, rule_id, str(hit.get("message") or "Heuristic finding"))
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _sarif_level(str(hit.get("severity") or "LOW")),
                    "message": {"text": str(hit.get("message") or spec)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": lockfile or spec},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                    "properties": {"ecosystem": eco, "package_spec": spec},
                }
            )

        for hit in summ.get("content_findings") or []:
            if not isinstance(hit, dict):
                continue
            rule_id = str(hit.get("rule_id") or "chaintrap/content")
            file_uri = str(hit.get("file") or lockfile or spec)
            hit_line = int(hit.get("line") or 1)
            _ensure_rule(rules_seen, rule_id, rule_id, str(hit.get("message") or "Content malware pattern"))
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _sarif_level(str(hit.get("severity") or "HIGH")),
                    "message": {"text": f"{spec}: {hit.get('message') or rule_id}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_uri},
                                "region": {"startLine": hit_line},
                            }
                        }
                    ],
                    "properties": {
                        "ecosystem": eco,
                        "package_spec": spec,
                        "snippet": str(hit.get("snippet") or "")[:240],
                    },
                }
            )

        if summ.get("osv_error"):
            rule_id = "chaintrap/osv-error"
            _ensure_rule(rules_seen, rule_id, "OSV query error", "Registry/OSV lookup failed")
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "warning",
                    "message": {"text": f"{spec}: {summ.get('osv_error')}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": lockfile or spec},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                    "properties": {"ecosystem": eco, "package_spec": spec},
                }
            )

        for vuln_id in summ.get("vulnerable_osv_ids") or []:
            rule_id = "chaintrap/cve"
            _ensure_rule(rules_seen, rule_id, "Known vulnerability", "OSV CVE/GHSA advisory")
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "warning",
                    "message": {"text": f"{spec}: {vuln_id}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": lockfile or spec},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                    "properties": {"ecosystem": eco, "package_spec": spec, "osv_id": vuln_id},
                }
            )

    for wf in wf_findings:
        if not isinstance(wf, dict):
            continue
        rule_id = str(wf.get("rule_id") or "chaintrap/workflow")
        _ensure_rule(
            rules_seen,
            rule_id,
            rule_id,
            str(wf.get("message") or "Workflow hardening finding"),
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(str(wf.get("severity") or "MEDIUM")),
                "message": {"text": str(wf.get("message") or rule_id)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(wf.get("file") or ".github/workflows")},
                            "region": {"startLine": int(wf.get("line") or 1)},
                        }
                    }
                ],
                "properties": {"category": "workflow"},
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tc/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Chaintrap",
                        "informationUri": "https://github.com/chaintrap-sec/scan-action",
                        "version": "1.0.0",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
                "properties": {
                    "bundle_id": bundle_id,
                    "source_repo": source_repo,
                    "source_ref": source_ref,
                },
            }
        ],
    }
