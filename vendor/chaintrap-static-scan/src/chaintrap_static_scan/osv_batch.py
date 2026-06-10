from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

_log = logging.getLogger(__name__)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
_MAX_READ = 4_000_000


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        v = default
    else:
        try:
            v = int(raw)
        except ValueError:
            v = default
    v = max(minimum, v)
    if maximum is not None:
        v = min(v, maximum)
    return v


def _env_float(name: str, default: float, *, minimum: float = 5.0) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        v = default
    else:
        try:
            v = float(raw)
        except ValueError:
            v = default
    return max(minimum, v)


def _batch_size() -> int:
    """OSV querybatch queries per HTTP request (default 1000; override CHAINTRAP_OSV_QUERYBATCH_SIZE)."""
    return _env_int("CHAINTRAP_OSV_QUERYBATCH_SIZE", 1000, minimum=1, maximum=1000)


def _timeout_sec() -> float:
    return _env_float("CHAINTRAP_OSV_QUERYBATCH_TIMEOUT", 180.0, minimum=10.0)

# OSV ecosystem strings
OSV_ECOSYSTEM_NPM = "npm"
OSV_ECOSYSTEM_PYPI = "PyPI"


def _osv_ecosystem(eco: str) -> str:
    e = (eco or "").strip().lower()
    if e == "pypi":
        return OSV_ECOSYSTEM_PYPI
    return OSV_ECOSYSTEM_NPM


def query_osv_querybatch(
    queries: list[tuple[str, str, str]],
) -> list[list[dict[str, Any]]]:
    """
    Run POST /v1/querybatch. Each query is (ecosystem_lower, package_name, version).

    Returns one list of raw OSV vuln dicts per query (same order as input).
    On failure, returns empty vuln lists for the whole chunk.
    """
    if not queries:
        return []

    results: list[list[dict[str, Any]]] = []
    bs = _batch_size()
    for i in range(0, len(queries), bs):
        chunk = queries[i : i + bs]
        body_obj = {
            "queries": [
                {
                    "package": {
                        "name": name,
                        "ecosystem": _osv_ecosystem(eco),
                    },
                    "version": version,
                }
                for eco, name, version in chunk
            ]
        }
        body = json.dumps(body_obj).encode("utf-8")
        req = urllib.request.Request(
            OSV_QUERYBATCH_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "chaintrap-static-scan/0.1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_timeout_sec()) as resp:
                raw = resp.read(_MAX_READ)
            data = json.loads(raw.decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as exc:
            _log.warning("OSV querybatch failed for chunk starting %s: %s", i, exc)
            for _ in chunk:
                results.append([])
            continue

        raw_results = data.get("results") or []
        for idx, _ in enumerate(chunk):
            vulns: list[dict[str, Any]] = []
            if idx < len(raw_results):
                for v in raw_results[idx].get("vulns") or []:
                    if isinstance(v, dict):
                        vulns.append(v)
            results.append(vulns)
    return results
