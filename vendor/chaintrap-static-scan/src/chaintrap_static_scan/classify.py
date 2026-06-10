from __future__ import annotations


def extract_vuln_ids_from_osv_vulns(vulns: list[dict]) -> list[str]:
    """Collect primary `id` from each OSV vuln object (aliases ignored for v1)."""
    out: list[str] = []
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        vid = (v.get("id") or "").strip()
        if vid:
            out.append(vid)
    return out


def classify_ids(all_ids: list[str]) -> tuple[list[str], list[str]]:
    """
    Split into malicious (MAL-*) vs vulnerable (everything else).
    Returns (malicious_sorted, vulnerable_sorted) unique stable lists.
    """
    mal = sorted({i for i in all_ids if i.upper().startswith("MAL-")})
    vuln = sorted({i for i in all_ids if not i.upper().startswith("MAL-")})
    return mal, vuln
