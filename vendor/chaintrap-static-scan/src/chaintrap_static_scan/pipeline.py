from __future__ import annotations

from chaintrap_static_scan.classify import classify_ids, extract_vuln_ids_from_osv_vulns
from chaintrap_static_scan.models import OsvFinding, PackageKey
from chaintrap_static_scan.osv_batch import query_osv_querybatch


def scan_packages(keys: list[PackageKey]) -> dict[PackageKey, OsvFinding]:
    """
    Query OSV for each unique (ecosystem, name, version), map findings back to every PackageKey.
    """
    if not keys:
        return {}

    out: dict[PackageKey, OsvFinding] = {}
    valid_keys: list[PackageKey] = []
    for k in keys:
        name = (k.name or "").strip()
        ver = (k.version or "").strip()
        if not name or not ver:
            out[k] = OsvFinding(
                malicious_ids=[],
                vulnerable_ids=[],
                query_error="missing name or version",
            )
        else:
            valid_keys.append(k)

    if not valid_keys:
        return out

    # Unique OSV query -> list of PackageKeys that need this result
    unique_order: list[tuple[str, str, str]] = []
    bucket: dict[tuple[str, str, str], list[PackageKey]] = {}
    for k in valid_keys:
        eco = k.ecosystem
        name = (k.name or "").strip()
        ver = (k.version or "").strip()
        t = (eco, name.lower(), ver)
        if t not in bucket:
            bucket[t] = []
            unique_order.append(t)
        bucket[t].append(k)

    queries = [(eco, name, ver) for eco, name, ver in unique_order]
    raw_lists = query_osv_querybatch(queries)

    for idx, t in enumerate(unique_order):
        vuln_objs = raw_lists[idx] if idx < len(raw_lists) else []
        ids = extract_vuln_ids_from_osv_vulns(vuln_objs)
        mal, vuln = classify_ids(ids)
        finding = OsvFinding(malicious_ids=mal, vulnerable_ids=vuln, query_error=None)
        for pk in bucket[t]:
            out[pk] = finding
    return out
