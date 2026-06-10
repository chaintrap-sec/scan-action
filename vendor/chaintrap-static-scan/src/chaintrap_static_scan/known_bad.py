"""OSV-independent known-bad package@version denylist (blocks before advisories land)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_RULE_ID = "CTC-KB001"
_CACHE: dict[str, Any] | None = None


def _default_data_path(data_dir: Path | None) -> Path | None:
    if data_dir is None:
        return None
    path = data_dir / "known_bad_packages.json"
    return path if path.is_file() else None


def load_known_bad(data_dir: Path | None = None) -> dict[str, Any]:
    """Load denylist JSON. Returns empty structure if missing."""
    global _CACHE
    path = _default_data_path(data_dir)
    if path is None:
        return {"version": 1, "npm": {}, "pypi": {}, "references": {}}
    if _CACHE is not None and _CACHE.get("_path") == str(path):
        return _CACHE
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "npm": {}, "pypi": {}, "references": {}}
    if not isinstance(doc, dict):
        return {"version": 1, "npm": {}, "pypi": {}, "references": {}}
    doc["_path"] = str(path)
    _CACHE = doc
    return doc


def clear_known_bad_cache() -> None:
    global _CACHE
    _CACHE = None


def match(
    ecosystem: str,
    name: str,
    version: str,
    *,
    data_dir: Path | None = None,
) -> dict[str, Any] | None:
    """
    Return a finding dict if (ecosystem, name, version) is on the denylist.
    Exact name+version match only.
    """
    eco = ecosystem.strip().lower()
    pkg_name = name.strip()
    ver = version.strip()
    if not eco or not pkg_name or not ver:
        return None
    doc = load_known_bad(data_dir)
    eco_map = doc.get(eco)
    if not isinstance(eco_map, dict):
        return None
    versions = eco_map.get(pkg_name)
    if not isinstance(versions, list):
        return None
    if ver not in versions:
        return None
    refs = doc.get("references") if isinstance(doc.get("references"), dict) else {}
    ref_key = f"{eco}:{pkg_name}@{ver}"
    ref = refs.get(ref_key) or refs.get(f"{eco}:{pkg_name}") or {}
    campaign = ""
    note = ""
    if isinstance(ref, dict):
        campaign = str(ref.get("campaign") or "")
        note = str(ref.get("note") or ref.get("url") or "")
    msg = f"Known-bad package on denylist: {pkg_name}@{ver}"
    if campaign:
        msg += f" ({campaign})"
    return {
        "rule_id": _RULE_ID,
        "severity": "CRITICAL",
        "category": "KNOWN_BAD",
        "message": msg,
        "campaign": campaign,
        "reference": note,
        "package": pkg_name,
        "version": ver,
        "ecosystem": eco,
    }
