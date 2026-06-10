"""Fetch tenant package IOC rows from Supabase PostgREST (read-only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def fetch_org_iocs(
    supabase_url: str,
    api_key: str,
    org_id: str,
    *,
    timeout: float = 60.0,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """
    Return active IOC rows keyed by (ecosystem, package_name_lower, package_version).

    Uses PostgREST on package_ioc_indicators with org_id filter.
    """
    base = (supabase_url or "").strip().rstrip("/")
    key = (api_key or "").strip()
    org = (org_id or "").strip()
    if not base or not key or not org:
        return {}
    if not base.lower().startswith("https://"):
        raise RuntimeError("IOC endpoint must use https://")

    params = urllib.parse.urlencode(
        {
            "org_id": f"eq.{org}",
            "active": "eq.true",
            "select": "ecosystem,package_name,package_version,severity,source,ioc_key",
        }
    )
    url = f"{base}/rest/v1/package_ioc_indicators?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "apikey": key,
            "Authorization": f"Bearer {key}",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Supabase IOC fetch HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Supabase IOC fetch failed: {exc}") from exc

    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Supabase IOC fetch returned invalid JSON: {exc}") from exc
    if not isinstance(rows, list):
        raise RuntimeError(f"Supabase IOC fetch expected JSON array, got {type(rows)!r}")

    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        eco = str(row.get("ecosystem") or "").strip().lower()
        name = str(row.get("package_name") or "").strip()
        ver = str(row.get("package_version") or "").strip()
        if not eco or not name or not ver:
            continue
        out[(eco, name.lower(), ver)] = row
    return out
