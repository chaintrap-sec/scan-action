from __future__ import annotations

import re
from pathlib import Path

from chaintrap_guard.lockfiles import read_project_pypi_lockfiles
from chaintrap_guard.models import PackageSpec, ParsedCommand

_INSTALL_SUBCOMMANDS = frozenset({"install", "i", "sync"})
_ADD_SUBCOMMANDS = frozenset({"add"})
_PIP_INSTALL = frozenset(_INSTALL_SUBCOMMANDS)
_UV_PIP_INSTALL = frozenset({"pip"})
_VALUE_FLAGS = frozenset({"-r", "--requirement", "-c", "--constraint", "-t", "--target"})

_REQ_LINE = re.compile(
    r"^\s*([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*(?:==\s*([^\s;#]+))?",
    re.MULTILINE,
)


def _parse_pip_token(token: str) -> PackageSpec | None:
    t = (token or "").strip()
    if not t or t.startswith("-") or "://" in t:
        return None
    if "@" in t and "://" in t.split("@", 1)[-1]:
        return None
    if "==" in t:
        name, _, ver = t.partition("==")
        return PackageSpec(name=name.strip(), version=ver.strip(), ecosystem="pypi")
    if ">=" in t or "<=" in t or "!=" in t or "~=" in t:
        name = re.split(r"[<>=!~]", t, maxsplit=1)[0].strip()
        return PackageSpec(name=name, version=t, ecosystem="pypi")
    return PackageSpec(name=t, version="", ecosystem="pypi")


def _requirements_file(path: Path) -> list[PackageSpec]:
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[PackageSpec] = []
    for m in _REQ_LINE.finditer(text):
        name = m.group(1)
        ver = (m.group(2) or "").strip()
        if name:
            out.append(PackageSpec(name=name, version=ver, ecosystem="pypi"))
    return out


def _collect_from_args(rest: list[str], *, cwd: Path | None) -> list[PackageSpec]:
    targets: list[PackageSpec] = []
    i = 0
    work = cwd or Path.cwd()
    while i < len(rest):
        tok = rest[i]
        if tok.startswith("-"):
            if tok in _VALUE_FLAGS and i + 1 < len(rest):
                if tok in ("-r", "--requirement"):
                    targets.extend(_requirements_file(work / rest[i + 1]))
                i += 2
            else:
                i += 1
            continue
        spec = _parse_pip_token(tok)
        if spec:
            targets.append(spec)
        i += 1
    return targets


def parse_pip(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    args = list(argv)
    if not args:
        return ParsedCommand(manager="pip", subcommand="", passthrough=True, raw_argv=argv)

    idx = 0
    while idx < len(args) and args[idx].startswith("-"):
        if args[idx] in ("-q", "-qq", "-v", "-vv") or not args[idx].startswith("--"):
            idx += 1
            continue
        idx += 1

    if idx >= len(args):
        return ParsedCommand(manager="pip", subcommand="", passthrough=True, raw_argv=argv)

    sub = args[idx].lower()
    if sub not in _PIP_INSTALL:
        return ParsedCommand(manager="pip", subcommand=sub, passthrough=True, raw_argv=argv)

    targets = _collect_from_args(args[idx + 1 :], cwd=cwd)
    if not targets and sub == "sync":
        targets = read_project_pypi_lockfiles(cwd)
    return ParsedCommand(
        manager="pip",
        subcommand=sub,
        targets=targets,
        manifest_only=not targets and sub == "sync",
        raw_argv=argv,
    )


def parse_uv(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    args = list(argv)
    if not args:
        return ParsedCommand(manager="uv", subcommand="", passthrough=True, raw_argv=argv)

    idx = 0
    while idx < len(args) and args[idx].startswith("-"):
        idx += 1

    if idx >= len(args):
        return ParsedCommand(manager="uv", subcommand="", passthrough=True, raw_argv=argv)

    sub = args[idx].lower()
    rest = args[idx + 1 :]

    if sub == "pip" and rest:
        inner_sub = rest[0].lower()
        if inner_sub in _PIP_INSTALL:
            targets = _collect_from_args(rest[1:], cwd=cwd)
            if not targets and inner_sub == "sync":
                targets = read_project_pypi_lockfiles(cwd)
            return ParsedCommand(
                manager="uv",
                subcommand=f"pip {inner_sub}",
                targets=targets,
                manifest_only=not targets and inner_sub == "sync",
                raw_argv=argv,
            )
        return ParsedCommand(manager="uv", subcommand=sub, passthrough=True, raw_argv=argv)

    if sub == "sync":
        targets = read_project_pypi_lockfiles(cwd)
        return ParsedCommand(
            manager="uv",
            subcommand=sub,
            targets=targets,
            manifest_only=True,
            raw_argv=argv,
        )

    if sub in _ADD_SUBCOMMANDS:
        targets = _collect_from_args(rest, cwd=cwd)
        return ParsedCommand(manager="uv", subcommand=sub, targets=targets, raw_argv=argv)

    return ParsedCommand(manager="uv", subcommand=sub, passthrough=True, raw_argv=argv)
