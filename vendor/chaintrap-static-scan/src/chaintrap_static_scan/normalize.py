"""
Mirror of extension-analyser `normalize_source_payloads` for agent-style JSON.
Keeps the CLI self-contained without importing FastAPI/api.* .
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ArtifactType = Literal["npm", "pypi", "extension", "mcp_server"]


@dataclass(frozen=True)
class NormalizedArtifact:
    source_file: str
    host_name: str
    artifact_type: ArtifactType
    name: str
    version: str


def _clean(v: object) -> str:
    if v is None:
        return ""
    if not isinstance(v, str):
        v = str(v)
    return v.strip()


def _inventory_row_ecosystem(kind: str, browser: str) -> str:
    """Match extension-analyser ``api.inventory_ecosystem.inventory_row_ecosystem`` (dashboard rules)."""
    b = (browser or "").strip().lower()
    if b in ("chrome", "edge"):
        return "browser_extension"
    if b == "vscode":
        return "vscode"
    if b == "openvsx":
        return "openvsx"
    k = (kind or "").strip().lower()
    if "chrome_extension" in k or "edge_extension" in k or "browser_extension" in k:
        return "browser_extension"
    if "vscode" in k:
        return "vscode"
    if "openvsx" in k:
        return "openvsx"
    if "o365" in k or "office" in k:
        return "o365"
    if "npm" in k:
        return "npm"
    if "pypi" in k or "python" in k:
        return "pypi"
    return "unknown"


def _split_package_spec(package_spec: str) -> tuple[str, str] | None:
    s = (package_spec or "").strip()
    if not s or "@" not in s:
        return None
    if s.startswith("@"):
        idx = s.rfind("@")
        if idx <= 0:
            return None
        name, ver = s[:idx], s[idx + 1 :]
    else:
        idx = s.find("@")
        if idx < 0:
            return None
        name, ver = s[:idx], s[idx + 1 :]
    name, ver = name.strip(), ver.strip()
    if not name or not ver:
        return None
    return (name, ver)


def _append_chaintrap_inventory_telemetry(
    out: list[NormalizedArtifact], file_name: str, payload: dict[str, Any]
) -> None:
    host = (
        _clean(payload.get("hostname"))
        or _clean(payload.get("hostName"))
        or _clean(payload.get("host_id"))
        or "unknown-host"
    )

    bundles = payload.get("bundles")
    if isinstance(bundles, list):
        for grp in bundles:
            if not isinstance(grp, list):
                continue
            for item in grp:
                if not isinstance(item, dict):
                    continue
                eco_raw = _clean(item.get("ecosystem")).lower()
                spec = item.get("package_spec") or item.get("packageSpec")
                if not isinstance(spec, str):
                    continue
                parsed = _split_package_spec(spec)
                if not parsed:
                    continue
                name, ver = parsed
                if eco_raw == "pypi":
                    at: ArtifactType = "pypi"
                elif eco_raw == "npm":
                    at = "npm"
                else:
                    continue
                _append_norm(
                    out,
                    source_file=file_name,
                    host_name=host,
                    artifact_type=at,
                    name=name,
                    version=ver,
                )

    inv = payload.get("inventory")
    if isinstance(inv, list):
        for row in inv:
            if not isinstance(row, dict):
                continue
            kind_raw = str(row.get("Kind") or row.get("kind") or "")
            kind = _clean(kind_raw).lower()
            browser = str(row.get("Browser") or row.get("browser") or "")
            ident = row.get("Identifier") or row.get("identifier")
            version = row.get("Version") or row.get("version")
            eco = _inventory_row_ecosystem(kind_raw, browser)
            if eco == "npm":
                _append_norm(
                    out,
                    source_file=file_name,
                    host_name=host,
                    artifact_type="npm",
                    name=ident,
                    version=version,
                )
            elif eco == "pypi":
                _append_norm(
                    out,
                    source_file=file_name,
                    host_name=host,
                    artifact_type="pypi",
                    name=ident,
                    version=version,
                )


def _append_norm(
    out: list[NormalizedArtifact],
    *,
    source_file: str,
    host_name: str,
    artifact_type: ArtifactType,
    name: object,
    version: object,
) -> None:
    n = _clean(name)
    v = _clean(version) or "unknown"
    h = _clean(host_name) or "unknown-host"
    if not n:
        return
    out.append(
        NormalizedArtifact(
            source_file=source_file,
            host_name=h,
            artifact_type=artifact_type,
            name=n,
            version=v,
        )
    )


def normalize_source_payloads(source_files: list[tuple[str, dict[str, Any]]]) -> list[NormalizedArtifact]:
    """
    Convert heterogeneous Chaintrap-Agent JSON payloads into a flat normalized list.
    Same shapes as api.agent_ingest_pipeline.normalize_source_payloads.
    """
    out: list[NormalizedArtifact] = []

    def ingest_host_blob(fn: str, host_blob: dict[str, Any], host_fallback: str) -> None:
        host_name = _clean(host_blob.get("hostName")) or _clean(host_blob.get("host_id")) or host_fallback

        for p in host_blob.get("packages", []) or []:
            if not isinstance(p, dict):
                continue
            eco = _clean(p.get("ecosystem")).lower()
            if eco == "pypi":
                at: ArtifactType = "pypi"
            else:
                at = "npm"
            _append_norm(
                out,
                source_file=fn,
                host_name=host_name,
                artifact_type=at,
                name=p.get("name") or p.get("package_name"),
                version=p.get("version") or p.get("package_version"),
            )

        for ext in host_blob.get("extensions", []) or []:
            if isinstance(ext, dict):
                _append_norm(
                    out,
                    source_file=fn,
                    host_name=host_name,
                    artifact_type="extension",
                    name=ext.get("name") or ext.get("extension_id") or ext.get("id"),
                    version=ext.get("version"),
                )
            else:
                _append_norm(
                    out,
                    source_file=fn,
                    host_name=host_name,
                    artifact_type="extension",
                    name=ext,
                    version="unknown",
                )

        for srv in host_blob.get("mcpServers", []) or host_blob.get("mcp_servers", []) or []:
            if isinstance(srv, dict):
                _append_norm(
                    out,
                    source_file=fn,
                    host_name=host_name,
                    artifact_type="mcp_server",
                    name=srv.get("name") or srv.get("id") or srv.get("server"),
                    version=srv.get("version"),
                )
            else:
                _append_norm(
                    out,
                    source_file=fn,
                    host_name=host_name,
                    artifact_type="mcp_server",
                    name=srv,
                    version="unknown",
                )

    for file_name, payload in source_files:
        if not isinstance(payload, dict):
            continue

        is_chaintrap = isinstance(payload.get("bundles"), list) or isinstance(payload.get("inventory"), list)
        if is_chaintrap:
            _append_chaintrap_inventory_telemetry(out, file_name, payload)
            inv_host = (
                _clean(payload.get("hostname"))
                or _clean(payload.get("hostName"))
                or _clean(payload.get("host_id"))
                or "unknown-host"
            )
            ch_hosts = payload.get("hosts")
            if isinstance(ch_hosts, list) and ch_hosts:
                for h in ch_hosts:
                    if isinstance(h, dict):
                        ingest_host_blob(file_name, h, inv_host)
            continue

        host_default = _clean(payload.get("hostName")) or _clean(payload.get("host_id")) or "unknown-host"
        hosts = payload.get("hosts")
        if isinstance(hosts, list) and hosts:
            for h in hosts:
                if isinstance(h, dict):
                    ingest_host_blob(file_name, h, host_default)
            continue
        ingest_host_blob(file_name, payload, host_default)
    return out
