"""Parse pnpm/yarn dlx and bunx ephemeral npm installs."""

from __future__ import annotations

from pathlib import Path

from chaintrap_guard.models import PackageSpec, ParsedCommand
from chaintrap_guard.parse_npm import _parse_spec


def _targets_after_dlx(argv: list[str]) -> list[PackageSpec]:
    if not argv or argv[0].lower() != "dlx":
        return []
    targets: list[PackageSpec] = []
    for tok in argv[1:]:
        if tok.startswith("-"):
            continue
        spec = _parse_spec(tok)
        if spec:
            targets.append(spec)
            break
    return targets


def parse_pnpm_dlx(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    _ = cwd
    targets = _targets_after_dlx(argv)
    if not targets:
        return ParsedCommand(manager="pnpm", subcommand=argv[0] if argv else "", passthrough=True, raw_argv=argv)
    return ParsedCommand(manager="pnpm", subcommand="dlx", targets=targets, raw_argv=argv)


def parse_yarn_dlx(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    _ = cwd
    targets = _targets_after_dlx(argv)
    if not targets:
        return ParsedCommand(manager="yarn", subcommand=argv[0] if argv else "", passthrough=True, raw_argv=argv)
    return ParsedCommand(manager="yarn", subcommand="dlx", targets=targets, raw_argv=argv)


def parse_bunx(argv: list[str], *, cwd: Path | None = None) -> ParsedCommand:
    _ = cwd
    targets: list[PackageSpec] = []
    for tok in argv:
        if tok.startswith("-"):
            continue
        spec = _parse_spec(tok)
        if spec:
            targets.append(spec)
            break
    if not targets:
        return ParsedCommand(manager="bunx", subcommand="", passthrough=True, raw_argv=argv)
    return ParsedCommand(manager="bunx", subcommand="exec", targets=targets, raw_argv=argv)
