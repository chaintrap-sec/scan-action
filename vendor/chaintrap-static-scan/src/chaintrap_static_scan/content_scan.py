"""Download package artifacts and run static content malware rules."""

from __future__ import annotations

import io
import logging
import tarfile
import tempfile
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any

from chaintrap_static_scan.http_utils import http_get_bytes, http_get_json
from chaintrap_static_scan.pattern_scanner import hits_to_dicts, scan_tree

_log = logging.getLogger(__name__)

_DEFAULT_MAX_BYTES = 10_485_760  # 10 MB
_DEFAULT_MAX_PACKAGES = 30


def _is_safe_tar_member(name: str) -> bool:
    p = Path(name)
    if p.is_absolute():
        return False
    return ".." not in p.parts


def safe_extract_tar(data: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for member in tf.getmembers():
            if not _is_safe_tar_member(member.name):
                raise ValueError(f"unsafe tar path: {member.name}")
        tf.extractall(dest, members=[m for m in tf.getmembers() if _is_safe_tar_member(m.name)])


def safe_extract_zip(data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if not _is_safe_tar_member(info.filename):
                raise ValueError(f"unsafe zip path: {info.filename}")
        for info in zf.infolist():
            if _is_safe_tar_member(info.filename):
                zf.extract(info, dest)


def _npm_tarball_url(name: str, version: str) -> str | None:
    enc = urllib.parse.quote(name, safe="@/")
    meta, err = http_get_json(f"https://registry.npmjs.org/{enc}/{version}")
    if err or not isinstance(meta, dict):
        return None
    dist = meta.get("dist") if isinstance(meta.get("dist"), dict) else {}
    url = str(dist.get("tarball") or "").strip()
    return url or None


def _pypi_artifact_url(name: str, version: str) -> tuple[str | None, str | None]:
    meta, err = http_get_json(f"https://pypi.org/pypi/{name}/{version}/json")
    if err or not isinstance(meta, dict):
        return None, err
    urls = meta.get("urls") or []
    if not isinstance(urls, list):
        return None, "no urls"
    wheel = next((u for u in urls if isinstance(u, dict) and u.get("packagetype") == "bdist_wheel"), None)
    sdist = next((u for u in urls if isinstance(u, dict) and u.get("packagetype") == "sdist"), None)
    chosen = wheel or sdist
    if not chosen:
        return None, "no wheel or sdist"
    url = str(chosen.get("url") or "").strip()
    return (url or None), None


def _download_and_extract(
    url: str,
    dest: Path,
    *,
    max_bytes: int,
) -> str | None:
    data, err = http_get_bytes(url, max_bytes=max_bytes)
    if err or data is None:
        return err or "download failed"
    lower = url.lower()
    try:
        if lower.endswith(".zip") or ".whl" in lower:
            safe_extract_zip(data, dest)
        else:
            safe_extract_tar(data, dest)
    except (ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        return str(exc)
    return None


def scan_package_content(
    ecosystem: str,
    name: str,
    version: str,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> tuple[list[dict[str, Any]], str | None]:
    """Download and scan one package. Returns (findings, error)."""
    eco = ecosystem.strip().lower()
    url: str | None = None
    if eco == "npm":
        url = _npm_tarball_url(name, version)
        if not url:
            return [], "npm tarball url not found"
    elif eco == "pypi":
        url, err = _pypi_artifact_url(name, version)
        if not url:
            return [], err or "pypi artifact url not found"
    else:
        return [], f"unsupported ecosystem: {eco}"

    with tempfile.TemporaryDirectory(prefix="chaintrap_content_") as td:
        dest = Path(td)
        dl_err = _download_and_extract(url, dest, max_bytes=max_bytes)
        if dl_err:
            return [], dl_err
        hits = scan_tree(dest, eco)
        return hits_to_dicts(hits), None


def scan_packages_content(
    packages: list[tuple[str, str, str]],
    *,
    max_packages: int = _DEFAULT_MAX_PACKAGES,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """
    Scan up to max_packages diff-added packages.
    Returns dict keyed by (ecosystem, name, version) with findings and optional error.
    """
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for pkg in packages[:max_packages]:
        eco, name, ver = pkg
        findings, err = scan_package_content(eco, name, ver, max_bytes=max_bytes)
        out[pkg] = {"findings": findings, "error": err}
        if err:
            _log.warning("content scan failed for %s@%s: %s", name, ver, err)
    return out
