from __future__ import annotations

import json
import re
from pathlib import Path

from chaintrap_guard.lockfiles import read_package_lock
from chaintrap_guard.models import PackageSpec, ParsedCommand

_INSTALL_SUBCOMMANDS = frozenset({"install", "i", "add", "ci", "update", "upgrade"})

# Flags that consume the next argv token
_VALUE_FLAGS = frozenset(
    {
        "-w",
        "--workspace",
        "-g",
        "--global",
        "--prefix",
        "-C",
        "--directory",
        "--install-links",
        "--target",
        "--os",
        "--arch",
        "--libc",
    }
)

_SPEC_RE = re.compile(r"^(@[^/]+/[^@]+|[^/@]+)(?:@(.+))?$")


def _parse_spec(token: str) -> PackageSpec | None:
    t = (token or "").strip()
    if not t or t.startswith("-") or t.startswith(".") or "/" in t and not t.startswith("@"):
        if t.startswith(".") or t.startswith("/"):
            return None
    if "://" in t:
        return None
    m = _SPEC_RE.match(t)
    if not m:
        return None
    name, ver = m.group(1), (m.group(2) or "").strip()
    return PackageSpec(name=name, version=ver, ecosystem="npm")


def _read_manifest_targets(cwd: Path | None) -> list[PackageSpec]:
    root = cwd or Path.cwd()
    pkg_json = root / "package.json"
    if not pkg_json.is_file():
        return []
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[PackageSpec] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            if isinstance(name, str) and name.strip():
                out.append(
                    PackageSpec(
                        name=name.strip(),
                        version=str(ver).strip() if ver is not None else "",
                        ecosystem="npm",
                    )
                )
    return out


def parse_npm(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    args = list(argv)
    if not args:
        return ParsedCommand(manager="npm", subcommand="", passthrough=True, raw_argv=argv)

    idx = 0
    while idx < len(args) and args[idx].startswith("-"):
        flag = args[idx]
        if flag in _VALUE_FLAGS and idx + 1 < len(args):
            idx += 2
            continue
        idx += 1

    if idx >= len(args):
        return ParsedCommand(manager="npm", subcommand="", passthrough=True, raw_argv=argv)

    sub = args[idx].lower()
    rest = args[idx + 1 :]

    if sub not in _INSTALL_SUBCOMMANDS:
        return ParsedCommand(
            manager="npm",
            subcommand=sub,
            passthrough=True,
            raw_argv=argv,
        )

    targets: list[PackageSpec] = []
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok.startswith("-"):
            if tok in _VALUE_FLAGS and i + 1 < len(rest):
                i += 2
            else:
                i += 1
            continue
        spec = _parse_spec(tok)
        if spec:
            targets.append(spec)
        i += 1

    root = cwd or Path.cwd()
    manifest_only = sub in {"ci", "update", "upgrade"} and not targets
    if sub == "ci":
        lock_targets = read_package_lock(root)
        if lock_targets:
            targets = lock_targets
            manifest_only = True
        elif manifest_only:
            targets = _read_manifest_targets(cwd)
    elif manifest_only:
        targets = _read_manifest_targets(cwd)

    return ParsedCommand(
        manager="npm",
        subcommand=sub,
        targets=targets,
        manifest_only=manifest_only,
        raw_argv=argv,
    )
