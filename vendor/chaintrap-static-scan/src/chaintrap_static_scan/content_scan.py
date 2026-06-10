"""Download package artifacts and run static content malware rules."""

from __future__ import annotations

import io
import logging
import os
import tarfile
import tempfile
import urllib.parse
import zipfile
from pathlib import Path
from collections.abc import Callable
from typing import Any

from chaintrap_static_scan.http_utils import http_get_bytes, http_get_json
from chaintrap_static_scan.pattern_scanner import hits_to_dicts, scan_tree

_log = logging.getLogger(__name__)


def _npm_registry_base() -> str:
    """npm registry base. Override for private mirrors or offline testing."""
    return os.environ.get("CHAINTRAP_NPM_REGISTRY", "https://registry.npmjs.org").rstrip("/")


def _pypi_base() -> str:
    """PyPI JSON API base. Override for private mirrors or offline testing."""
    return os.environ.get("CHAINTRAP_PYPI_BASE", "https://pypi.org/pypi").rstrip("/")

_DEFAULT_MAX_BYTES = 10_485_760  # 10 MB compressed download cap
_DEFAULT_MAX_PACKAGES = 30
_MAX_EXTRACTED_BYTES = 209_715_200  # 200 MB total uncompressed cap (decompression bomb guard)
_MAX_EXTRACTED_FILES = 20_000


def _is_safe_member_path(name: str) -> bool:
    if not name:
        return False
    p = Path(name)
    if p.is_absolute():
        return False
    # Reject drive-absolute / UNC on Windows-style names too.
    norm = name.replace("\\", "/")
    if norm.startswith("/") or ":" in norm.split("/", 1)[0]:
        return False
    return ".." not in p.parts


def _within_dest(dest: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(dest.resolve())
        return True
    except ValueError:
        return False


def safe_extract_tar(
    data: bytes,
    dest: Path,
    *,
    max_total_bytes: int = _MAX_EXTRACTED_BYTES,
    max_files: int = _MAX_EXTRACTED_FILES,
) -> None:
    dest_resolved = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        members = tf.getmembers()
        total = 0
        count = 0
        safe_members = []
        for m in members:
            # Reject symlinks/hardlinks outright — classic tar-slip via link target.
            if m.issym() or m.islnk():
                raise ValueError(f"unsafe link member: {m.name}")
            if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
                raise ValueError(f"unsafe special member: {m.name}")
            if not _is_safe_member_path(m.name):
                raise ValueError(f"unsafe tar path: {m.name}")
            target = dest_resolved / m.name
            if not _within_dest(dest_resolved, target):
                raise ValueError(f"tar path escapes dest: {m.name}")
            if m.isfile():
                total += max(0, m.size)
                count += 1
                if total > max_total_bytes:
                    raise ValueError("extracted size exceeds cap (possible decompression bomb)")
                if count > max_files:
                    raise ValueError("extracted file count exceeds cap")
            safe_members.append(m)
        try:
            # Python 3.12+: "data" filter also strips setuid/dev bits and double-checks paths.
            tf.extractall(dest, members=safe_members, filter="data")
        except TypeError:
            tf.extractall(dest, members=safe_members)


def safe_extract_zip(
    data: bytes,
    dest: Path,
    *,
    max_total_bytes: int = _MAX_EXTRACTED_BYTES,
    max_files: int = _MAX_EXTRACTED_FILES,
) -> None:
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        total = 0
        count = 0
        for info in zf.infolist():
            if not _is_safe_member_path(info.filename):
                raise ValueError(f"unsafe zip path: {info.filename}")
            target = dest_resolved / info.filename
            if not _within_dest(dest_resolved, target):
                raise ValueError(f"zip path escapes dest: {info.filename}")
            if not info.is_dir():
                total += max(0, info.file_size)
                count += 1
                if total > max_total_bytes:
                    raise ValueError("extracted size exceeds cap (possible decompression bomb)")
                if count > max_files:
                    raise ValueError("extracted file count exceeds cap")
        for info in zf.infolist():
            if _is_safe_member_path(info.filename):
                zf.extract(info, dest)


def _npm_tarball_url(name: str, version: str) -> str | None:
    enc = urllib.parse.quote(name, safe="@/")
    meta, err = http_get_json(f"{_npm_registry_base()}/{enc}/{version}")
    if err or not isinstance(meta, dict):
        return None
    dist = meta.get("dist") if isinstance(meta.get("dist"), dict) else {}
    url = str(dist.get("tarball") or "").strip()
    return url or None


def _pypi_artifact_url(name: str, version: str) -> tuple[str | None, str | None]:
    meta, err = http_get_json(f"{_pypi_base()}/{name}/{version}/json")
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


def scan_extracted_tree(dest: Path, ecosystem: str) -> list[dict[str, Any]]:
    """Run pattern scan on an already-extracted package tree."""
    return hits_to_dicts(scan_tree(dest, ecosystem.strip().lower()))


def scan_package_content(
    ecosystem: str,
    name: str,
    version: str,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    extra_findings_fn: Callable[[Path, str], list[dict[str, Any]]] | None = None,
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
        findings = scan_extracted_tree(dest, eco)
        if extra_findings_fn is not None:
            findings.extend(extra_findings_fn(dest, eco))
        return findings, None


def scan_packages_content(
    packages: list[tuple[str, str, str]],
    *,
    max_packages: int = _DEFAULT_MAX_PACKAGES,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    extra_findings_fn: Callable[[Path, str], list[dict[str, Any]]] | None = None,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """
    Scan up to max_packages diff-added packages.
    Returns dict keyed by (ecosystem, name, version) with findings and optional error.
    """
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for pkg in packages[:max_packages]:
        eco, name, ver = pkg
        findings, err = scan_package_content(
            eco, name, ver, max_bytes=max_bytes, extra_findings_fn=extra_findings_fn
        )
        out[pkg] = {"findings": findings, "error": err}
        if err:
            _log.warning("content scan failed for %s@%s: %s", name, ver, err)
    return out
