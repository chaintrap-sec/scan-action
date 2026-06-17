"""Parse uvx and uv tool run ephemeral PyPI tool installs."""

from __future__ import annotations

from pathlib import Path

from chaintrap_guard.models import PackageSpec, ParsedCommand
from chaintrap_guard.parse_pip import _parse_pip_token


def _first_pypi_target(argv: list[str]) -> list[PackageSpec]:
    targets: list[PackageSpec] = []
    for tok in argv:
        if tok.startswith("-"):
            continue
        spec = _parse_pip_token(tok.replace("@", "==", 1) if "@" in tok and "==" not in tok else tok)
        if spec and spec.name:
            targets.append(spec)
            break
    return targets


def parse_uvx(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    """uvx <pkg>[@ver] or uvx --from pkg ver ..."""
    _ = cwd
    args = list(argv)
    if not args:
        return ParsedCommand(manager="uvx", subcommand="", passthrough=True, raw_argv=argv)

    targets: list[PackageSpec] = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in ("--from", "-f") and i + 1 < len(args):
            spec = _parse_pip_token(args[i + 1].replace("@", "==", 1) if "@" in args[i + 1] else args[i + 1])
            if spec:
                targets.append(spec)
            break
        if not tok.startswith("-"):
            spec = _parse_pip_token(tok.replace("@", "==", 1) if "@" in tok and "==" not in tok else tok)
            if spec:
                targets.append(spec)
            break
        i += 1

    if not targets:
        return ParsedCommand(manager="uvx", subcommand="", passthrough=True, raw_argv=argv)
    return ParsedCommand(manager="uvx", subcommand="exec", targets=targets, raw_argv=argv)


def parse_uv_tool_run(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    """uv tool run <pkg> — argv is ['tool', 'run', ...] or ['run', ...] after uv."""
    _ = cwd
    args = [a.lower() for a in argv]
    if args[:2] == ["tool", "run"]:
        rest = argv[2:]
    elif args and args[0] == "run":
        rest = argv[1:]
    else:
        return ParsedCommand(manager="uv", subcommand="tool", passthrough=True, raw_argv=argv)

    targets = _first_pypi_target(rest)
    if not targets:
        return ParsedCommand(manager="uv", subcommand="tool run", passthrough=True, raw_argv=argv)
    return ParsedCommand(manager="uv", subcommand="tool run", targets=targets, raw_argv=argv)
