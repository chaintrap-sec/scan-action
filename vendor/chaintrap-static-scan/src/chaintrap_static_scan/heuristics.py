"""Registry metadata heuristics: release age, install scripts, typosquat."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

_DEFAULT_POPULAR = (
    "react",
    "lodash",
    "express",
    "axios",
    "webpack",
    "typescript",
    "next",
    "vue",
    "angular",
    "eslint",
    "prettier",
    "moment",
    "request",
    "chalk",
    "commander",
    "dotenv",
    "uuid",
    "mongoose",
    "redis",
    "jest",
    "requests",
    "pandas",
    "numpy",
    "flask",
    "django",
    "boto3",
    "pytest",
    "pip",
    "setuptools",
    "urllib3",
    "certifi",
    "cryptography",
)


def _load_popular_names(data_dir: Path | None) -> list[str]:
    if data_dir:
        path = data_dir / "popular_packages.txt"
        if path.is_file():
            lines = [
                ln.strip().lower()
                for ln in path.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")
            ]
            if lines:
                return lines
    return list(_DEFAULT_POPULAR)


def _fetch_json(url: str, timeout: float = 20.0) -> dict[str, Any] | None:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        return None


def _parse_release_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = str(raw).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(text.replace("+00:00", "Z"), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _name_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def check_release_age(
    ecosystem: str,
    name: str,
    version: str,
    *,
    minimum_days: int = 7,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    eco = ecosystem.strip().lower()
    now = now or datetime.now(timezone.utc)
    published: datetime | None = None

    if eco == "npm":
        enc = name.replace("/", "%2F")
        data = _fetch_json(f"https://registry.npmjs.org/{enc}/{version}")
        if data and isinstance(data, dict):
            published = _parse_release_date(str(data.get("time") or data.get("published") or ""))
            if not published and isinstance(data.get("time"), dict):
                published = _parse_release_date(str(data["time"].get(version) or ""))
    elif eco == "pypi":
        data = _fetch_json(f"https://pypi.org/pypi/{name}/{version}/json")
        if data and isinstance(data, dict):
            urls = data.get("urls") or []
            if isinstance(urls, list) and urls:
                published = _parse_release_date(str(urls[0].get("upload_time") or ""))
            if not published:
                info = data.get("info") if isinstance(data.get("info"), dict) else {}
                published = _parse_release_date(str(info.get("release_date") or ""))

    if not published:
        return None
    age_days = (now - published).total_seconds() / 86400.0
    if age_days >= minimum_days:
        return None
    return {
        "rule_id": "CTH-001",
        "severity": "MEDIUM",
        "message": f"{name}@{version} published {age_days:.1f} days ago (< {minimum_days}d)",
        "age_days": round(age_days, 2),
        "published_at": published.isoformat(),
    }


def check_install_scripts(ecosystem: str, name: str, version: str) -> dict[str, Any] | None:
    if ecosystem.strip().lower() != "npm":
        return None
    enc = name.replace("/", "%2F")
    data = _fetch_json(f"https://registry.npmjs.org/{enc}/{version}")
    if not data or not isinstance(data, dict):
        return None
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    risky = [k for k in ("preinstall", "postinstall", "prepare", "install") if k in scripts]
    if not risky:
        return None
    return {
        "rule_id": "CTH-002",
        "severity": "MEDIUM",
        "message": f"{name}@{version} has lifecycle scripts: {', '.join(risky)}",
        "scripts": risky,
    }


def check_typosquat(
    ecosystem: str,
    name: str,
    *,
    data_dir: Path | None = None,
    similarity_threshold: float = 0.82,
) -> dict[str, Any] | None:
    pkg = name.strip().lower()
    if pkg.startswith("@"):
        return None
    popular = _load_popular_names(data_dir)
    if pkg in popular:
        return None
    best_name = ""
    best_score = 0.0
    for candidate in popular:
        score = _name_similarity(pkg, candidate)
        if score > best_score:
            best_score = score
            best_name = candidate
    if best_score < similarity_threshold or not best_name:
        return None
    if pkg == best_name:
        return None
    return {
        "rule_id": "CTH-003",
        "severity": "LOW",
        "message": f"{name} resembles popular package '{best_name}' (similarity {best_score:.0%})",
        "similar_to": best_name,
        "similarity": round(best_score, 3),
    }


def run_heuristics(
    ecosystem: str,
    name: str,
    version: str,
    *,
    minimum_release_age_days: int = 7,
    check_age: bool = True,
    check_scripts: bool = True,
    check_typo: bool = True,
    data_dir: Path | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if check_age and minimum_release_age_days > 0:
        hit = check_release_age(
            ecosystem, name, version, minimum_days=minimum_release_age_days
        )
        if hit:
            findings.append(hit)
    if check_scripts:
        hit = check_install_scripts(ecosystem, name, version)
        if hit:
            findings.append(hit)
    if check_typo:
        hit = check_typosquat(ecosystem, name, data_dir=data_dir)
        if hit:
            findings.append(hit)
    return findings
