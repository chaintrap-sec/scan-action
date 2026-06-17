from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request


def version_needs_resolve(version: str) -> bool:
    s = (version or "").strip().lower()
    if not s:
        return True
    return s in ("unknown", "*", "latest")


def _timeout() -> float:
    try:
        t = float((os.environ.get("CHAINTRAP_REGISTRY_HTTP_TIMEOUT") or "12").strip())
    except ValueError:
        t = 12.0
    return max(3.0, min(t, 60.0))


def fetch_npm_latest(package_name: str) -> str | None:
    name = (package_name or "").strip()
    if not name:
        return None
    path = name.replace("/", "%2F") if name.startswith("@") else name
    url = f"https://registry.npmjs.org/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "chaintrap-guard/0.1"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None
    dist_tags = data.get("dist-tags") or {}
    latest = dist_tags.get("latest")
    return str(latest).strip() if latest else None


def fetch_pypi_latest(package_name: str) -> str | None:
    name = (package_name or "").strip()
    if not name:
        return None
    url = f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "chaintrap-guard/0.1"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None
    info = data.get("info") or {}
    ver = info.get("version")
    return str(ver).strip() if ver else None


def resolve_version(ecosystem: str, name: str, version: str, *, enabled: bool) -> str:
    if not enabled or not version_needs_resolve(version):
        return (version or "").strip()
    eco = ecosystem.strip().lower()
    if eco == "npm":
        latest = fetch_npm_latest(name)
    elif eco == "pypi":
        latest = fetch_pypi_latest(name)
    else:
        latest = None
    return latest or (version or "").strip()
