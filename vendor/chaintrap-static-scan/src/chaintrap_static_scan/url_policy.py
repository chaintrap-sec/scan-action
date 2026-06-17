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


def validate_npm_tarball_url(url: str, *, registry_base: str | None = None) -> str | None:
    extra = ()
    if registry_base:
        h = _registry_host_from_base(registry_base)
        if h:
            extra = (h,)
    return validate_https_url(url, allowed_suffixes=_NPM_CDN_SUFFIXES + extra)


def validate_pypi_artifact_url(url: str, *, pypi_base: str | None = None) -> str | None:
    extra: tuple[str, ...] = ()
    if pypi_base:
        h = _registry_host_from_base(pypi_base)
        if h:
            extra = (h,)
    return validate_https_url(url, allowed_suffixes=_PYPI_CDN_SUFFIXES + extra)
