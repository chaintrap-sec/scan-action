"""Parse lockfile package_spec into name and version (no network)."""

from __future__ import annotations


def split_package_spec(ecosystem: str, package_spec: str) -> tuple[str, str]:
    eco = (ecosystem or "").strip().lower()
    raw = (package_spec or "").strip()
    if not raw:
        raise ValueError("empty package_spec")
    if eco == "npm":
        if raw.startswith("@"):
            name, _, ver = raw[1:].partition("@")
            pkg = f"@{name}" if name else raw
        elif "@" in raw:
            name, ver = raw.rsplit("@", 1)
            pkg = name.strip()
        else:
            raise ValueError(f"npm package_spec missing version: {package_spec!r}")
        if not ver.strip():
            raise ValueError(f"npm package_spec missing version: {package_spec!r}")
        return pkg, ver.strip()
    if eco == "pypi":
        if "@" not in raw:
            raise ValueError(f"pypi package_spec missing version: {package_spec!r}")
        name, ver = raw.rsplit("@", 1)
        if not name.strip() or not ver.strip():
            raise ValueError(f"invalid pypi package_spec: {package_spec!r}")
        return name.strip(), ver.strip()
    raise ValueError(f"unsupported ecosystem: {ecosystem!r}")


def ioc_lookup_key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    return (ecosystem.strip().lower(), name.strip().lower(), version.strip())


def format_ioc_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem.strip().lower()}:{name}@{version}"
