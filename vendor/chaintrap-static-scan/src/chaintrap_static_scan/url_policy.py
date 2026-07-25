"""HTTPS URL host policy for outbound requests (SSRF mitigation)."""

from __future__ import annotations

import ipaddress
import os
import socket
import urllib.parse


def _parse_host(url: str) -> str | None:
    try:
        parsed = urllib.parse.urlparse(url.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() != "https":
        return None
    host = (parsed.hostname or "").strip().lower()
    return host or None


def _is_blocked_ip(host: str) -> bool:
    """True if host resolves to or is a blocked address."""
    if not host:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved

    blocked_names = {
        "localhost",
        "metadata.google.internal",
        "169.254.169.254",
    }
    if host in blocked_names:
        return True
    try:
        for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
    except OSError:
        pass
    return False


def _host_matches_suffix(host: str, suffix: str) -> bool:
    return host == suffix.rstrip(".") or host.endswith("." + suffix.lstrip("."))


def validate_https_url(
    url: str,
    *,
    allowed_suffixes: tuple[str, ...],
    allow_hosts: frozenset[str] | None = None,
) -> str | None:
    """
    Return None if URL is allowed, else an error message.
    Blocks non-HTTPS, blocked IPs, and hosts outside allowed_suffixes/allow_hosts.
    """
    host = _parse_host(url)
    if not host:
        return "URL must use https:// with a valid host"
    if _is_blocked_ip(host):
        return f"blocked host: {host}"
    if allow_hosts and host in allow_hosts:
        return None
    for suffix in allowed_suffixes:
        if _host_matches_suffix(host, suffix):
            return None
    return f"host not allowed: {host}"


def validate_supabase_url(url: str) -> str | None:
    return validate_https_url(
        url,
        allowed_suffixes=("supabase.co", "supabase.in"),
    )


def _extra_api_hosts() -> frozenset[str]:
    raw = os.environ.get("CHAINTRAP_API_ALLOW_HOSTS", "")
    return frozenset(x.strip().lower() for x in raw.split(",") if x.strip())


def validate_api_report_url(url: str) -> str | None:
    return validate_https_url(
        url,
        allowed_suffixes=("chaintrap.com",),
        allow_hosts=_extra_api_hosts(),
    )


_NPM_CDN_SUFFIXES = (
    "registry.npmjs.org",
    "npm.pkg.github.com",
    "registry.yarnpkg.com",
)

_PYPI_CDN_SUFFIXES = (
    "files.pythonhosted.org",
    "pypi.org",
)


def _registry_host_from_base(base_url: str) -> str | None:
    host = _parse_host(base_url if "://" in base_url else f"https://{base_url}")
    return host


def _default_port(scheme: str) -> int | None:
    s = scheme.lower()
    if s == "https":
        return 443
    if s == "http":
        return 80
    return None


def _same_origin(url: str, base: str) -> bool:
    """True when url and base share scheme+host+port (path ignored).

    Lets offline/mock registries (http://127.0.0.1:PORT) serve artifacts from the
    same origin when CHAINTRAP_NPM_REGISTRY / CHAINTRAP_PYPI_BASE point there.
    Production CDN hosts still go through the HTTPS allowlist.
    """
    try:
        u = urllib.parse.urlparse(url.strip())
        b_raw = base.strip()
        b = urllib.parse.urlparse(b_raw if "://" in b_raw else f"https://{b_raw}")
    except ValueError:
        return False
    if not u.scheme or not b.scheme or not u.hostname or not b.hostname:
        return False
    if u.scheme.lower() != b.scheme.lower():
        return False
    if u.hostname.lower() != b.hostname.lower():
        return False
    return (u.port or _default_port(u.scheme)) == (b.port or _default_port(b.scheme))


def validate_npm_tarball_url(url: str, *, registry_base: str | None = None) -> str | None:
    if registry_base and _same_origin(url, registry_base):
        return None
    extra = ()
    if registry_base:
        h = _registry_host_from_base(registry_base)
        if h:
            extra = (h,)
    return validate_https_url(url, allowed_suffixes=_NPM_CDN_SUFFIXES + extra)


def validate_pypi_artifact_url(url: str, *, pypi_base: str | None = None) -> str | None:
    if pypi_base and _same_origin(url, pypi_base):
        return None
    extra: tuple[str, ...] = ()
    if pypi_base:
        h = _registry_host_from_base(pypi_base)
        if h:
            extra = (h,)
    return validate_https_url(url, allowed_suffixes=_PYPI_CDN_SUFFIXES + extra)
