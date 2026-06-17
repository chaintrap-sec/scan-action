"""Parse pipx run ephemeral PyPI tool installs."""

from __future__ import annotations

from pathlib import Path

from chaintrap_guard.models import PackageSpec, ParsedCommand
from chaintrap_guard.parse_pip import _parse_pip_token


def parse_pipx(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    """pipx run <pkg> or pipx run --spec pkg==ver"""
    _ = cwd
    args = list(argv)
    if not args:
        return ParsedCommand(manager="pipx", subcommand="", passthrough=True, raw_argv=argv)

    idx = 0
    while idx < len(args) and args[idx].startswith("-"):
        idx += 1
    if idx >= len(args) or args[idx].lower() != "run":
        return ParsedCommand(manager="pipx", subcommand=args[idx] if idx < len(args) else "", passthrough=True, raw_argv=argv)

    rest = args[idx + 1 :]
    targets: list[PackageSpec] = []
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in ("--spec", "-s") and i + 1 < len(rest):
            spec = _parse_pip_token(rest[i + 1])
            if spec:
                targets.append(spec)
            break
        if not tok.startswith("-"):
            spec = _parse_pip_token(tok)
            if spec:
                targets.append(spec)
            break
        i += 1

    if not targets:
        return ParsedCommand(manager="pipx", subcommand="run", passthrough=True, raw_argv=argv)
    return ParsedCommand(manager="pipx", subcommand="run", targets=targets, raw_argv=argv)
