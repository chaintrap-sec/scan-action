"""Registry metadata heuristics: release age, install scripts, typosquat."""

from __future__ import annotations

import os
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from chaintrap_static_scan.http_utils import http_get_json

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

_HEURISTIC_WORKERS = 8


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


def _npm_registry_base() -> str:
    return os.environ.get("CHAINTRAP_NPM_REGISTRY", "https://registry.npmjs.org").rstrip("/")


def _npm_version_url(name: str, version: str) -> str:
    enc = urllib.parse.quote(name, safe="@/")
    return f"{_npm_registry_base()}/{enc}/{version}"


def _fetch_npm_version_meta(name: str, version: str) -> dict[str, Any] | None:
    data, _err = http_get_json(_npm_version_url(name, version))
    return data if isinstance(data, dict) else None


def _release_age_from_npm_meta(
    data: dict[str, Any],
    *,
    name: str,
    version: str,
    minimum_days: int,
    now: datetime,
) -> dict[str, Any] | None:
    published = _parse_release_date(str(data.get("time") or data.get("published") or ""))
    if not published and isinstance(data.get("time"), dict):
        published = _parse_release_date(str(data["time"].get(version) or ""))
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


def _install_scripts_from_npm_meta(
    data: dict[str, Any],
    *,
    name: str,
    version: str,
) -> dict[str, Any] | None:
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


def check_release_age(
    ecosystem: str,
    name: str,
    version: str,
    *,
    minimum_days: int = 7,
    now: datetime | None = None,
    npm_meta: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    eco = ecosystem.strip().lower()
    now = now or datetime.now(timezone.utc)
    published: datetime | None = None

    if eco == "npm":
        data = npm_meta if npm_meta is not None else _fetch_npm_version_meta(name, version)
        if data:
            return _release_age_from_npm_meta(
                data, name=name, version=version, minimum_days=minimum_days, now=now
            )
        return None
    if eco == "pypi":
        data, _err = http_get_json(f"https://pypi.org/pypi/{name}/{version}/json")
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


def check_install_scripts(
    ecosystem: str,
    name: str,
    version: str,
    *,
    npm_meta: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if ecosystem.strip().lower() != "npm":
        return None
    data = npm_meta if npm_meta is not None else _fetch_npm_version_meta(name, version)
    if not data:
        return None
    return _install_scripts_from_npm_meta(data, name=name, version=version)


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
    check_provenance: bool = True,
    check_dep_confusion: bool = True,
    data_dir: Path | None = None,
    npm_meta: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    eco = ecosystem.strip().lower()
    if eco == "npm" and npm_meta is None and (check_age or check_scripts):
        npm_meta = _fetch_npm_version_meta(name, version)

    if check_age and minimum_release_age_days > 0:
        hit = check_release_age(
            ecosystem,
            name,
            version,
            minimum_days=minimum_release_age_days,
            npm_meta=npm_meta,
        )
        if hit:
            findings.append(hit)
    if check_scripts:
        hit = check_install_scripts(ecosystem, name, version, npm_meta=npm_meta)
        if hit:
            findings.append(hit)
    if check_typo:
        hit = check_typosquat(ecosystem, name, data_dir=data_dir)
        if hit:
            findings.append(hit)
    if check_provenance:
        hit = check_missing_provenance(ecosystem, name, version, npm_meta=npm_meta)
        if hit:
            findings.append(hit)
    if check_dep_confusion:
        hit = check_dependency_confusion(ecosystem, name, data_dir=data_dir)
        if hit:
            findings.append(hit)
    return findings


def check_install_script_new_in_version(
    ecosystem: str,
    name: str,
    version: str,
    *,
    npm_meta: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a finding if this version introduces lifecycle scripts not present in the previous version."""
    if ecosystem.strip().lower() != "npm":
        return None
    data = npm_meta if npm_meta is not None else _fetch_npm_version_meta(name, version)
    if not data:
        return None
    current_scripts = set(data.get("scripts", {}).keys()) & {"preinstall", "postinstall", "prepare", "install"}
    if not current_scripts:
        return None
    # Attempt to compare against the previous version
    all_versions: list[str] = []
    try:
        from chaintrap_static_scan.http_utils import http_get_json as _get

        pkg_data, _ = _get(f"{_npm_registry_base()}/{name}")
        if pkg_data and isinstance(pkg_data, dict):
            all_versions = list((pkg_data.get("versions") or {}).keys())
    except Exception:
        pass

    if len(all_versions) < 2:
        return None
    try:
        idx = all_versions.index(version)
    except ValueError:
        return None
    if idx == 0:
        return None
    prev_version = all_versions[idx - 1]
    prev_data, _ = (
        __import__(
            "chaintrap_static_scan.http_utils", fromlist=["http_get_json"]
        ).http_get_json(f"{_npm_registry_base()}/{name}/{prev_version}")
    )
    if not prev_data or not isinstance(prev_data, dict):
        return None
    prev_scripts = set(prev_data.get("scripts", {}).keys()) & {"preinstall", "postinstall", "prepare", "install"}
    newly_added = current_scripts - prev_scripts
    if not newly_added:
        return None
    return {
        "rule_id": "CTH-004",
        "severity": "HIGH",
        "message": f"{name}@{version} introduces new lifecycle scripts not present in {prev_version}: {', '.join(sorted(newly_added))}",
        "newly_added_scripts": sorted(newly_added),
        "previous_version": prev_version,
    }


def check_missing_provenance(
    ecosystem: str,
    name: str,
    version: str,
    *,
    npm_meta: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a finding if the package lacks SLSA provenance / attestation."""
    eco = ecosystem.strip().lower()
    if eco != "npm":
        return None
    data = npm_meta if npm_meta is not None else _fetch_npm_version_meta(name, version)
    if not data:
        return None
    dist = data.get("dist") or {}
    has_attestation = bool(dist.get("attestations") or data.get("_attestations"))
    if has_attestation:
        return None
    return {
        "rule_id": "CTH-005",
        "severity": "LOW",
        "message": f"{name}@{version} has no SLSA provenance attestation — consider verifying via npm audit signatures",
    }


def check_dependency_confusion(
    ecosystem: str,
    name: str,
    *,
    data_dir: Path | None = None,
) -> dict[str, Any] | None:
    """Flag scoped packages published to a public registry that appear to be internal names."""
    eco = ecosystem.strip().lower()
    if eco != "npm":
        return None
    if not name.startswith("@"):
        return None
    scope, _, pkg = name[1:].partition("/")
    scope = scope.lower()
    internal_scopes: set[str] = set()
    if data_dir:
        path = data_dir / "internal_scopes.txt"
        if path.is_file():
            internal_scopes = {
                ln.strip().lstrip("@").lower()
                for ln in path.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")
            }
    # Heuristic: single-word scopes matching common internal patterns
    internal_indicators = {"internal", "private", "corp", "company", "local", "intranet"}
    if scope in internal_scopes or scope in internal_indicators or pkg.startswith("internal-"):
        return {
            "rule_id": "CTH-006",
            "severity": "MEDIUM",
            "message": f"{name} appears to be an internal-scope package published on the public registry — verify this is intentional (dependency confusion risk)",
        }
    return None


def run_heuristics_batch(
    packages: list[tuple[str, str, str]],
    *,
    minimum_release_age_days: int = 7,
    data_dir: Path | None = None,
    max_workers: int = _HEURISTIC_WORKERS,
) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    """Run heuristics for many packages in parallel. Key: (ecosystem, name, version)."""
    if not packages:
        return {}

    npm_meta_cache: dict[tuple[str, str], dict[str, Any] | None] = {}

    def _one(pkg: tuple[str, str, str]) -> tuple[tuple[str, str, str], list[dict[str, Any]]]:
        eco, name, ver = pkg
        npm_meta = None
        if eco == "npm":
            key = (name, ver)
            if key not in npm_meta_cache:
                npm_meta_cache[key] = _fetch_npm_version_meta(name, ver)
            npm_meta = npm_meta_cache[key]
        hits = run_heuristics(
            eco,
            name,
            ver,
            minimum_release_age_days=minimum_release_age_days,
            data_dir=data_dir,
            npm_meta=npm_meta,
        )
        return pkg, hits

    out: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    workers = min(max_workers, max(1, len(packages)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, pkg) for pkg in packages]
        for fut in as_completed(futures):
            key, hits = fut.result()
            out[key] = hits
    return out
