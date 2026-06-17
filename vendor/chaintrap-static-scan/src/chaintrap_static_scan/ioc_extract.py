"""Extract and defang IOCs from content-scan matched lines for safe PR/SARIF display."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

_MAX_PER_TYPE = 5

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}(?![\d.])"
)
_DOMAIN_RE = re.compile(
    r"(?<![\w@/])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![\w.])",
    re.IGNORECASE,
)
_CURL_WGET_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|&;]{0,200}",
    re.IGNORECASE,
)
_POWERSHELL_RE = re.compile(r"\bpowershell\b[^\n]{0,160}", re.IGNORECASE)
_EXEC_SYNC_RE = re.compile(r"\bexecSync\s*\([^)]{0,120}\)", re.IGNORECASE)

_BENIGN_HOSTS = frozenset(
    {
        "registry.npmjs.org",
        "www.npmjs.com",
        "npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "github.com",
        "raw.githubusercontent.com",
        "nodejs.org",
        "unpkg.com",
        "cdn.jsdelivr.net",
    }
)

_SKIP_IPS = frozenset({"127.0.0.1", "0.0.0.0", "255.255.255.255"})

_COMMAND_CATEGORIES = frozenset(
    {
        "PROCESS_EXECUTION",
        "process",
        "INSTALL_HOOK",
        "installer_hook",
        "EXFILTRATION",
        "exfiltration",
        "NETWORK_DOWNLOAD",
        "network",
        "DROPPER",
        "dropper",
        "SUPPLY_CHAIN_ABUSE",
    }
)

_METADATA_RULES = frozenset({"CTC-CRED013"})


def defang_ip(ip: str) -> str:
    return ip.strip().replace(".", "[.]")


def defang_domain(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if not host:
        return ""
    return host.replace(".", "[.]")


def defang_url(url: str) -> str:
    raw = url.strip().rstrip(".,;)]}'\"")
    if not raw:
        return ""
    scheme_sep = "://"
    if scheme_sep not in raw.lower():
        return raw
    scheme, rest = raw.split("://", 1)
    scheme_lower = scheme.lower()
    if scheme_lower == "https":
        out_scheme = "hxxps"
    elif scheme_lower == "http":
        out_scheme = "hxxp"
    else:
        out_scheme = scheme_lower

    slash = rest.find("/")
    if slash == -1:
        host_part = rest
        path_part = ""
    else:
        host_part = rest[:slash]
        path_part = rest[slash:]

    if "@" in host_part:
        _user, host_part = host_part.rsplit("@", 1)
    if ":" in host_part and not host_part.startswith("["):
        host_only, port = host_part.rsplit(":", 1)
        if port.isdigit():
            host_part = f"{defang_domain(host_only)}:{port}"
        else:
            host_part = defang_domain(host_part)
    else:
        host_part = defang_domain(host_part)

    return f"{out_scheme}://{host_part}{path_part}"


def _dedupe_cap(items: list[str], limit: int = _MAX_PER_TYPE) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _host_from_url(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _is_benign_host(host: str, *, rule_id: str) -> bool:
    if not host:
        return True
    h = host.lower().strip(".")
    if h in _BENIGN_HOSTS:
        return True
    if h.endswith(".githubusercontent.com") or h.endswith(".npmjs.org"):
        return True
    if rule_id.startswith("CTC-EXFIL") or rule_id in {"http_url_literal_ipv4", "tor_onion_url"}:
        return False
    return h in _BENIGN_HOSTS


def _should_extract_commands(category: str, rule_id: str) -> bool:
    cat = (category or "").strip()
    if cat in _COMMAND_CATEGORIES:
        return True
    if rule_id.startswith(("CTC-PE", "CTC-TTP", "CTC-IH", "CTC-EXFIL")):
        return True
    return False


def extract_artifacts(
    text: str,
    *,
    rule_id: str = "",
    category: str = "",
) -> dict[str, list[str]]:
    """Return defanged urls, domains, ips, commands extracted from matched line."""
    if not text or not text.strip():
        return {"urls": [], "domains": [], "ips": [], "commands": []}

    rid = (rule_id or "").strip()
    cat = (category or "").strip()

    raw_urls: list[str] = []
    for m in _URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;)]}'\"")
        if u:
            raw_urls.append(u)

    defanged_urls: list[str] = []
    domains_from_urls: list[str] = []
    for u in raw_urls:
        host = _host_from_url(u)
        if _is_benign_host(host, rule_id=rid):
            continue
        defanged_urls.append(defang_url(u))
        if host and not _IPV4_RE.fullmatch(host):
            domains_from_urls.append(defang_domain(host))

    ips: list[str] = []
    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        if ip in _SKIP_IPS and rid not in _METADATA_RULES:
            continue
        if ip == "169.254.169.254" and rid not in _METADATA_RULES:
            continue
        ips.append(defang_ip(ip))

    domains: list[str] = list(domains_from_urls)
    for m in _DOMAIN_RE.finditer(text):
        d = m.group(0).lower().rstrip(".")
        if _IPV4_RE.fullmatch(d):
            continue
        if _is_benign_host(d, rule_id=rid):
            continue
        domains.append(defang_domain(d))

    commands: list[str] = []
    if _should_extract_commands(cat, rid):
        for cre in (_CURL_WGET_RE, _POWERSHELL_RE, _EXEC_SYNC_RE):
            for m in cre.finditer(text):
                frag = m.group(0).strip()
                if len(frag) < 8:
                    continue
                for u in _URL_RE.findall(frag):
                    host = _host_from_url(u)
                    if host and not _is_benign_host(host, rule_id=rid):
                        frag = frag.replace(u, defang_url(u))
                commands.append(frag[:200])

    return {
        "urls": _dedupe_cap(defanged_urls),
        "domains": _dedupe_cap(domains),
        "ips": _dedupe_cap(ips),
        "commands": _dedupe_cap(commands),
    }


def enrich_content_hit(hit: dict[str, Any]) -> dict[str, Any]:
    """Attach defanged artifacts dict to a content finding."""
    out = dict(hit)
    text = str(hit.get("snippet") or "")
    artifacts = extract_artifacts(
        text,
        rule_id=str(hit.get("rule_id") or ""),
        category=str(hit.get("category") or ""),
    )
    out["artifacts"] = artifacts
    return out


def primary_artifact_label(artifacts: dict[str, list[str]] | None) -> str | None:
    """Best single artifact for SARIF message suffix."""
    if not artifacts:
        return None
    for key in ("urls", "commands", "domains", "ips"):
        vals = artifacts.get(key) or []
        if vals:
            return str(vals[0])
    return None
